import Std.Async.TCP
import Std.Time
import Tls.Client
import HaclStar.Hex

/-!
One-shot loopback TLS client harness for the external interoperability gate:
the counterpart of `Test.TlsExternalServer`, driving this repository's client
engine against an independently implemented server (OpenSSL `s_server`).

    tls_external_client PORT CA-PEM [--p256-hrr]

It connects to 127.0.0.1:PORT, verifies the server's chain against CA-PEM and
the name "localhost", and logs one line per event for the gate to check:
`NEGOTIATED retried=<bool>`, `EXPORTER <hex>` (RFC 9846 §7.5, label
"EXPERIMENTAL-tls13-lean", no context, 32 bytes), and `RESPONSE <first line>`
for a `GET /`. With `--p256-hrr` the first ClientHello lists P-256 without a
share, so a server restricted to P-256 must answer with a HelloRetryRequest.
-/

open Std.Async
open Tls

private def logLine (line : String) : IO Unit := do
  IO.println line
  (← IO.getStdout).flush

private def sendBytes (socket : TCP.Socket.Client) (bytes : ByteArray) : IO Unit := do
  unless bytes.isEmpty do
    (socket.send bytes).block

private partial def completeHandshake (socket : TCP.Socket.Client) (state : Client.State) :
    IO Client.State := do
  if state.connected then
    pure state
  else
    let some chunk ← (socket.recv? 16384).block
      | throw (IO.userError "server closed during TLS handshake")
    match Client.feedWithFailure state chunk with
    | .error failure =>
        if let some description := failure.error.fatalAlertDescription? then
          if let .ok alert := Client.sealFatalAlert failure.state description then
            sendBytes socket alert.wireBytes
        throw (IO.userError s!"TLS client: {failure.error}")
    | .ok output =>
        sendBytes socket output.wireBytes
        completeHandshake socket output.state

private partial def readResponse (socket : TCP.Socket.Client) (state : Client.State)
    (received : ByteArray) : IO (ByteArray × Client.State) := do
  if state.peerClosed || received.size > 65536 then
    pure (received, state)
  else
    match ← (socket.recv? 16384).block with
    | none => pure (received, state)
    | some chunk =>
        match Client.feed state chunk with
        | .error error => throw (IO.userError s!"TLS client: {error}")
        | .ok output =>
            sendBytes socket output.wireBytes
            readResponse socket output.state (received ++ output.plaintext)

def main (args : List String) : IO Unit := do
  let (encodedPort, caPath, hrr) ← match args with
    | [port, ca] => pure (port, ca, false)
    | [port, ca, "--p256-hrr"] => pure (port, ca, true)
    | _ => throw (IO.userError "usage: tls_external_client PORT CA-PEM [--p256-hrr]")
  let some port := encodedPort.toNat?
    | throw (IO.userError s!"invalid TCP port: {encodedPort}")
  let trustStore ← match TLS13.X509.Chain.TrustStore.decodePEM (← IO.FS.readFile caPath) with
    | .ok store => pure store
    | .error error => throw (IO.userError error)
  let now := (← Std.Time.Timestamp.now).toSecondsSinceUnixEpoch.toInt
  let clientRandom ← IO.getRandomBytes 32
  let x25519Private ← IO.getRandomBytes 32
  let p256Scalar ← IO.getRandomBytes 32
  let config : Client.Config := {
    clientRandom
    x25519Private
    p256Private := if hrr then some p256Scalar else none
    p256FirstFlightShare := !hrr
    serverName := some "localhost"
    alpnProtocols := #["http/1.1"]
    peerAuth := some { trustStore, now, hostname := "localhost" }
  }
  let started ← match Client.start config with
    | .ok output => pure output
    | .error error => throw (IO.userError s!"TLS client start: {error}")

  let socket ← TCP.Socket.Client.mk
  (socket.connect (.v4 { addr := Std.Net.IPv4Addr.ofParts 127 0 0 1, port := UInt16.ofNat port })).block
  try
    sendBytes socket started.wireBytes
    let connected ← completeHandshake socket started.state
    logLine s!"NEGOTIATED retried={connected.retried} alpn={connected.alpnSelected}"
    match Client.exportKeyingMaterial connected "EXPERIMENTAL-tls13-lean".toUTF8
        ByteArray.empty 32 with
    | .ok material => logLine s!"EXPORTER {HaclStar.Hex.encode material}"
    | .error error => logLine s!"EXPORTER-ERROR {error}"
    -- RFC 9846 §4.6.3: update our sending epoch and ask the server to update
    -- its own, then send the request under the new keys.
    let updated ← match Client.updateKeys connected (requestPeer := true) with
      | .ok output => pure output
      | .error error => throw (IO.userError s!"TLS KeyUpdate: {error}")
    sendBytes socket updated.wireBytes
    let readSecret := connected.readKeys?.map (·.secret)
    let request := "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".toUTF8
    let sent ← match Client.sealApplication updated.state request with
      | .ok output => pure output
      | .error error => throw (IO.userError s!"TLS application request: {error}")
    sendBytes socket sent.wireBytes
    let (response, final) ← readResponse socket sent.state ByteArray.empty
    logLine s!"PEER_UPDATED {final.readKeys?.map (·.secret) != readSecret}"
    let text := String.fromUTF8? response |>.getD ""
    logLine s!"RESPONSE {(text.splitOn "\r\n").headD ""}"
  finally
    try (socket.shutdown).block catch _ => pure ()
