import Tls.Client
import Tls.Server

/-!
Client-side HelloRetryRequest (RFC 9846 §4.1.4), driven in process with
hand-built server messages: the second ClientHello and its transcript, the
cookie echo, the ServerHello that must match the retry, and every refusal the
RFC requires. The external interop gate runs the same path against OpenSSL.
-/

open Tls

private def expect (label : String) (condition : Bool) : IO Unit := do
  unless condition do
    throw (IO.userError s!"{label}: assertion failed")

private def expectEq [BEq α] (label : String) (actual expected : α) : IO Unit :=
  expect label (actual == expected)

private def ok (label : String) (result : Except ε α) [ToString ε] : IO α :=
  match result with
  | .ok value => pure value
  | .error error => throw (IO.userError s!"{label}: {error}")

private instance : ToString Client.Error := ⟨Client.Error.render⟩

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
    let hi := (hexNibble? chars[2 * i]!).getD 0
    let lo := (hexNibble? chars[2 * i + 1]!).getD 0
    out := out.push (hi * 16 + lo)
  out

private def u16 (n : Nat) : ByteArray := ByteArray.mk #[UInt8.ofNat (n / 256), UInt8.ofNat n]

private def extension (type : Nat) (body : ByteArray) : ByteArray :=
  u16 type ++ u16 body.size ++ body

/-- A HelloRetryRequest with any extensions after supported_versions and
key_share, framed by hand so tests can add a cookie or an unoffered extension. -/
private def retryWith (sessionId : ByteArray) (group : Handshake.NamedGroup)
    (extra : ByteArray := ByteArray.empty) (suite : Nat := 0x1303) : IO ByteArray := do
  let extensions := extension 43 (u16 0x0304) ++ extension 51 (u16 group.toUInt16.toNat) ++ extra
  let body := u16 0x0303 ++ Handshake.helloRetryRequestRandom ++
    ByteArray.mk #[UInt8.ofNat sessionId.size] ++ sessionId ++ u16 suite ++
    ByteArray.mk #[0] ++ u16 extensions.size ++ extensions
  let message ← ok "frame HelloRetryRequest" (Handshake.frame Handshake.serverHelloType body)
  ok "HelloRetryRequest record" (Record.encodePlaintext .handshake message.encoded)

private def helloOf (wire : ByteArray) : IO Handshake.ClientHello := do
  let (_, records) ← ok "decode ClientHello record" (({} : Record.Decoder).feed wire)
  let some record := records[0]? | throw (IO.userError "no ClientHello record")
  let message ← ok "decode ClientHello" (Handshake.decode record.fragment)
  ok "parse ClientHello" (Handshake.parseClientHello message)

private def expectError (label : String) (result : Except Client.Error Client.Output)
    (alert : UInt8) : IO Unit :=
  match result with
  | .ok _ => throw (IO.userError s!"{label}: accepted")
  | .error error =>
      unless error.fatalAlertDescription? == some alert do
        throw (IO.userError s!"{label}: {error.render} (alert {error.fatalAlertDescription?})")

def main : IO Unit := do
  let sessionId := fill 32 0x57
  let p256Private := hex "c88f01f510d9ac3f70a292daa2316de544e9aab8afe84049c62a9c57862d1433"
  let config : Client.Config := {
    clientRandom := fill 32 0x13
    x25519Private := fill 32 0x24
    p256Private := some p256Private
    p256FirstFlightShare := false
    legacySessionId := sessionId
    serverName := some "localhost"
    alpnProtocols := #["h2"]
  }
  let started ← ok "start" (Client.start config)
  let first ← helloOf started.wireBytes
  expectEq "first flight carries only an X25519 share"
    (first.keyShares.map (·.group)) #[.x25519]
  expectEq "first flight lists P-256" first.supportedGroups #[.x25519, .secp256r1]

  -- A legal retry to P-256, with a cookie.
  let cookie := u16 5 ++ "c00k1".toUTF8
  let retryWire ← retryWith sessionId .secp256r1 (extension 44 cookie)
  let retried ← ok "accept HelloRetryRequest" (Client.feed started.state retryWire)
  expect "retry recorded" retried.state.retried
  expectEq "still waiting for ServerHello" retried.state.phase .waitingServerHello
  expect "no keys derived by a retry"
    (retried.state.readKeys?.isNone && retried.state.writeKeys?.isNone)
  let second ← helloOf retried.wireBytes
  expectEq "second ClientHello carries only the P-256 share"
    (second.keyShares.map (·.group)) #[.secp256r1]
  expectEq "same random" second.random first.random
  expectEq "same session id" second.legacySessionId first.legacySessionId
  expectEq "cookie echoed verbatim"
    ((second.extensions.find? (·.extensionType == Handshake.cookieExtension)).map (·.data))
    (some cookie)
  -- This repository's server enforces RFC 9846 §4.1.2's "the same ClientHello
  -- except key_share (and cookie)" rule. It never sends a cookie, so it
  -- refuses one; check a cookie-free retry against it.
  let plainRetry ← ok "cookie-free retry"
    (Client.feed started.state (← retryWith sessionId .secp256r1))
  expect "the server's §4.1.2 check accepts the second ClientHello"
    ((Server.checkRetryClientHello first (← helloOf plainRetry.wireBytes) .secp256r1).toBool)

  -- The transcript: message_hash(Hash(ClientHello1)) ‖ HelloRetryRequest ‖ ClientHello2.
  let (_, retryRecords) ← ok "decode retry" (({} : Record.Decoder).feed retryWire)
  let messageHash ← ok "message_hash"
    (Handshake.frame Handshake.messageHashType (HaclStar.sha256 first.encoded))
  expectEq "transcript after the retry" retried.state.transcript
    (messageHash.encoded ++ retryRecords[0]!.fragment ++ second.encoded)

  -- The ServerHello must match the retry's group.
  let some serverP256 := HaclStar.P256.publicKey
      (hex "c6ef9c5d78ae012a011164acb397ce2088685d8f06bf9be0b283ab46476bee53")
    | throw (IO.userError "P-256 fixture key rejected")
  let helloP256 ← ok "ServerHello P-256"
    (Handshake.encodeServerHello (fill 32 0x35) sessionId .secp256r1 serverP256)
  let helloP256Wire ← ok "record" (Record.encodePlaintext .handshake helloP256.encoded)
  let accepted ← ok "ServerHello after retry" (Client.feed retried.state helloP256Wire)
  expectEq "handshake keys after the retried ServerHello" accepted.state.phase
    .waitingEncryptedExtensions
  let helloX25519 ← ok "ServerHello X25519"
    (Handshake.encodeServerHello (fill 32 0x35) sessionId .x25519
      (HaclStar.X25519.base (fill 32 0x46)))
  let helloX25519Wire ← ok "record" (Record.encodePlaintext .handshake helloX25519.encoded)
  expectError "ServerHello disagreeing with the retry"
    (Client.feed retried.state helloX25519Wire) 47

  -- Refusals RFC 9846 §4.1.4 requires.
  expectError "a second HelloRetryRequest"
    (Client.feed retried.state (← retryWith sessionId .secp256r1)) 10
  expectError "a retry to a group the ClientHello already has a share for"
    (Client.feed started.state (← retryWith sessionId .x25519)) 47
  expectError "a retry echoing another session id"
    (Client.feed started.state (← retryWith (fill 32 0x58) .secp256r1)) 47
  expectError "a retry selecting a cipher suite that was not offered"
    (Client.feed started.state (← retryWith sessionId .secp256r1 (suite := 0x1301))) 47
  expectError "a retry carrying an extension the client did not offer"
    (Client.feed started.state (← retryWith sessionId .secp256r1 (extension 16 (u16 0)))) 110
  expectError "a retry with a malformed cookie"
    (Client.feed started.state (← retryWith sessionId .secp256r1 (extension 44 (u16 9)))) 50
  let x25519Only ← ok "start without P-256"
    (Client.start { config with p256Private := none })
  expectError "a retry to a group the ClientHello did not list"
    (Client.feed x25519Only.state (← retryWith sessionId .secp256r1)) 47

  IO.println "TLS client HelloRetryRequest regression passed"
