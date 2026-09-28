import Tls.Client
import Tls.Server

/-!
Session tickets and PSK resumption (RFC 9846 §2.2, §4.2.11, §4.6.1) between this
repository's own client and server, in process: a full handshake, a ticket, a
resumed handshake without certificates, and every way a resumption must fail
or fall back to a full handshake. The interop gate resumes with OpenSSL and Go.
-/

open Tls

private def expect (label : String) (condition : Bool) : IO Unit := do
  unless condition do
    throw (IO.userError s!"{label}: assertion failed")

private def expectEq [BEq α] (label : String) (actual expected : α) : IO Unit :=
  expect label (actual == expected)

private def client (label : String) (result : Except Client.Error α) : IO α :=
  match result with
  | .ok value => pure value
  | .error error => throw (IO.userError s!"{label}: {error.render}")

private def server (label : String) (result : Except Server.Error α) : IO α :=
  match result with
  | .ok value => pure value
  | .error error => throw (IO.userError s!"{label}: {error.render}")

private def fill (count : Nat) (octet : UInt8) : ByteArray :=
  ByteArray.mk (List.replicate count octet).toArray

private def hexNibble? (char : Char) : Option UInt8 :=
  if '0' ≤ char && char ≤ '9' then some (char.toNat - '0'.toNat).toUInt8
  else if 'a' ≤ char && char ≤ 'f' then some (char.toNat - 'a'.toNat + 10).toUInt8
  else none

private def hex (encoded : String) : ByteArray := Id.run do
  let chars := encoded.toList.toArray
  let mut out := ByteArray.empty
  for i in [0:chars.size / 2] do
    out := out.push ((hexNibble? chars[2 * i]!).getD 0 * 16 + (hexNibble? chars[2 * i + 1]!).getD 0)
  out

/-- One handshake between the engines; returns both connected states and the
server's first flight. -/
private def handshake (clientConfig : Client.Config) (serverConfig : Server.Config) :
    IO (Client.State × Server.State × ByteArray) := do
  let started ← client "start" (Client.start clientConfig)
  let flight ← server "server flight" (Server.feed (Server.start serverConfig) started.wireBytes)
  let finished ← client "client Finished" (Client.feed started.state flight.wireBytes)
  expect "client connected" finished.state.connected
  let done ← server "server connected" (Server.feed flight.state finished.wireBytes)
  expect "server connected" done.state.connected
  pure (finished.state, done.state, flight.wireBytes)

def main : IO Unit := do
  let pem ← IO.FS.readFile "Test/Fixtures/Tls/server_cert.pem"
  let some certificate := (TLS13.X509.PEM.decodeCertificates pem).toOption.bind (·[0]?)
    | throw (IO.userError "server certificate fixture")
  let ticketKey := fill 32 0x5a
  let serverConfig : Server.Config := {
    serverRandom := fill 32 0x33
    x25519Private := fill 32 0x44
    certificateChain := #[certificate]
    signingKey := hex "471761974da12938977eca1b40cc0ea3d6e9c52897648a1661681e88fd31f4be"
    ticketKey := some ticketKey
    ticketLifetime := 3600
    nowMs := 1_800_000_000_000
  }
  let clientConfig : Client.Config := {
    clientRandom := fill 32 0x11
    x25519Private := fill 32 0x22
    serverName := some "localhost"
  }

  -- A full handshake, then two tickets.
  let (clientState, serverState, fullFlight) ← handshake clientConfig serverConfig
  expect "a full handshake is not resumed" (!clientState.resumed && !serverState.resumed)
  let firstTicket ← server "issue ticket" (Server.issueTicket serverState 0x01020304 (fill 12 1))
  let secondTicket ← server "issue second ticket"
    (Server.issueTicket firstTicket.state 0x0a0b0c0d (fill 12 2))
  let received ← client "receive tickets"
    (Client.feed clientState (firstTicket.wireBytes ++ secondTicket.wireBytes))
  expectEq "two tickets kept" received.state.tickets.size 2
  let ticket := received.state.tickets[0]!
  expect "each ticket carries its own PSK (distinct ticket_nonce)"
    (ticket.psk != received.state.tickets[1]!.psk)
  expectEq "ticket_age_add kept" ticket.ageAdd 0x01020304
  expectEq "lifetime kept" ticket.lifetime 3600
  match Server.issueTicket { serverState with ticketKey := none } 0 (fill 12 3) with
  | .error (.invalidConfig _) => pure ()
  | _ => throw (IO.userError "server issued a ticket without a ticket key")

  -- Resumption: no Certificate or CertificateVerify, and both ends agree.
  let resumeConfig := { clientConfig with
    clientRandom := fill 32 0x12, x25519Private := fill 32 0x23
    resumption := some ticket, ticketAgeMs := 5000 }
  let later := { serverConfig with serverRandom := fill 32 0x34, nowMs := serverConfig.nowMs + 5000 }
  let (resumedClient, resumedServer, resumedFlight) ← handshake resumeConfig later
  expect "client resumed" resumedClient.resumed
  expect "server resumed" resumedServer.resumed
  expect "the resumed flight omits the certificate"
    (resumedFlight.size + 200 < fullFlight.size)
  let label := "EXPERIMENTAL-tls13-lean".toUTF8
  let clientExport ← client "client export"
    (Client.exportKeyingMaterial resumedClient label ByteArray.empty 32)
  let serverExport ← server "server export"
    (Server.exportKeyingMaterial resumedServer label ByteArray.empty 32)
  expectEq "a resumed connection exports the same keying material" clientExport serverExport
  let request := "resumed".toUTF8
  let sealed ← client "seal" (Client.sealApplication resumedClient request)
  let opened ← server "open" (Server.feed resumedServer sealed.wireBytes)
  expectEq "data over the resumed connection" opened.plaintext request
  -- A resumed connection issues tickets of its own.
  let chained ← server "ticket from a resumed connection"
    (Server.issueTicket resumedServer 7 (fill 12 4))
  let chainedClient ← client "receive" (Client.feed resumedClient chained.wireBytes)
  expectEq "resumed connection receives a ticket" chainedClient.state.tickets.size 1

  -- A tampered binder is fatal with decrypt_error (RFC 9846 §4.2.11).
  let started ← client "start" (Client.start resumeConfig)
  let wire := started.wireBytes
  let tampered := wire.set! (wire.size - 1) (wire.get! (wire.size - 1) ^^^ 1)
  match Server.feed (Server.start later) tampered with
  | .error error => expectEq "bad binder alert" error.fatalAlertDescription? (some 51)
  | .ok _ => throw (IO.userError "server accepted a tampered PSK binder")

  -- Fallbacks to a full handshake, which then succeeds.
  for (label, config) in [
      ("an expired ticket",
        { later with nowMs := serverConfig.nowMs + 3600 * 1000 + 1 }),
      ("a ticket sealed under another key",
        { later with ticketKey := some (fill 32 0x5b) }),
      ("a server without tickets", { later with ticketKey := none })] do
    let (c, s, _) ← handshake resumeConfig config
    expect s!"{label} falls back to a full handshake" (!c.resumed && !s.resumed)

  IO.println "TLS resumption regression passed"
