import Tls.Client
import Tls.Server

/-!
Post-handshake client authentication (RFC 9846 §4.2.6, §4.6.2) between this
repository's engines, in process: a server asks for a certificate after the
handshake, the client answers under its application epoch, and the server
validates the chain and the Finished; plus the refusals the RFC requires.
-/

open Tls

private def expect (label : String) (condition : Bool) : IO Unit := do
  unless condition do throw (IO.userError s!"{label}: assertion failed")

private def get [ToString ε] (result : Except ε α) : IO α :=
  match result with
  | .ok value => pure value
  | .error error => throw (IO.userError (toString error))

private def expectEq' [BEq α] (label : String) (actual expected : α) : IO Unit :=
  expect label (actual == expected)

private instance : ToString Client.Error := ⟨Client.Error.render⟩
private instance : ToString Server.Error := ⟨Server.Error.render⟩

private def load (name : String) : IO (ByteArray × TLS13.X509.Certificate) := do
  let pem ← IO.FS.readFile s!"Test/Fixtures/Identity/{name}.pem"
  let der := (← get (TLS13.X509.PEM.decodeCertificates pem))[0]!
  pure (der, ← get (TLS13.X509.Certificate.decode der))

private def key (name : String) : IO ByteArray := do
  let der ← IO.FS.readBinFile s!"Test/Fixtures/Identity/{name}-key.der"
  pure (der.extract 16 48)

private def bytes (value : UInt8) : ByteArray := ByteArray.mk (Array.replicate 32 value)

/-- Handshake, then one or more post-handshake authentications. -/
private def connect (client : Client.Config) (server : Server.Config) :
    IO (Client.State × Server.State) := do
  let hello ← get (Client.start client)
  let flight ← get (Server.feed (Server.start server) hello.wireBytes)
  let finished ← get (Client.feed hello.state flight.wireBytes)
  let done ← get (Server.feed flight.state finished.wireBytes)
  expect "both connected" (finished.state.connected && done.state.connected)
  pure (finished.state, done.state)

/-- One request, answer, and verification; returns both states after it. -/
private def authenticate (client : Client.State) (server : Server.State) (context : ByteArray) :
    IO (Client.State × Server.State) := do
  let request ← get (Server.requestClientCertificate server context)
  let answer ← get (Client.feed client request.wireBytes)
  expect "the client answers the CertificateRequest" (!answer.wireBytes.isEmpty)
  let verified ← get (Server.feed request.state answer.wireBytes)
  pure (answer.state, verified.state)

def main : IO Unit := do
  let (rootDer, root) ← load "root"
  let (clientDer, clientCert) ← load "client"
  let (serverDer, _) ← load "server"
  let now := clientCert.tbsCertificate.validity.notBefore.unixSeconds + 3600
  let identity ← get (Identity.create #[clientDer, rootDer] (← key "client") .clientAuth now true)
  let trust : TLS13.X509.Chain.TrustStore := { anchors := #[root] }
  let clientConfig : Client.Config := {
    clientRandom := bytes 1
    x25519Private := bytes 2
    identity := some identity
    peerAuth := some { trustStore := trust, now, hostname := "localhost" }
    postHandshakeAuth := true }
  let serverConfig : Server.Config := {
    serverRandom := bytes 3
    x25519Private := bytes 4
    certificateChain := #[serverDer, rootDer]
    signingKey := ← key "server"
    postHandshakeAuth := some { trustStore := trust, now } }

  -- The handshake authenticates only the server; the client proves itself later.
  let (client, server) ← connect clientConfig serverConfig
  expect "no client certificate during the handshake" server.peerCertificates.isEmpty
  let (client, server) ← authenticate client server "first".toUTF8
  expectEq' "one post-handshake authentication" server.postHandshakeAuthentications 1
  expect "the validated client chain" (server.peerCertificates.size == 2 &&
    server.peerCertificates[0]!.encoded == clientDer)
  -- Data still flows, and a second authentication works on the same connection.
  let sealed ← get (Client.sealApplication client "after".toUTF8)
  let opened ← get (Server.feed server sealed.wireBytes)
  expect "data after post-handshake authentication" (opened.plaintext == "after".toUTF8)
  let (_, again) ← authenticate sealed.state opened.state "second".toUTF8
  expectEq' "two post-handshake authentications" again.postHandshakeAuthentications 2

  -- One request at a time, with a non-empty context.
  let pending ← get (Server.requestClientCertificate server "x".toUTF8)
  match Server.requestClientCertificate pending.state "y".toUTF8 with
  | .error (.invalidConfig _) => pure ()
  | _ => throw (IO.userError "a second CertificateRequest while one is outstanding")
  match Server.requestClientCertificate server ByteArray.empty with
  | .error (.invalidConfig _) => pure ()
  | _ => throw (IO.userError "a CertificateRequest with an empty context")

  -- A client without an identity answers with an empty Certificate: refused
  -- when the policy requires one, accepted (no new peer) when it does not.
  let (anonymous, strict) ← connect { clientConfig with identity := none, peerAuth := none }
    serverConfig
  let request ← get (Server.requestClientCertificate strict "anon".toUTF8)
  let answer ← get (Client.feed anonymous request.wireBytes)
  match Server.feed request.state answer.wireBytes with
  | .error .clientCertificateRequired => pure ()
  | _ => throw (IO.userError "an empty client Certificate satisfied a required policy")
  let (anonymous, lenient) ← connect { clientConfig with identity := none, peerAuth := none }
    { serverConfig with postHandshakeAuth := some { trustStore := trust, now, required := false } }
  let (_, lenient) ← authenticate anonymous lenient "optional".toUTF8
  expect "an optional authentication completes without a certificate"
    (lenient.postHandshakeAuthentications == 1 && lenient.peerCertificates.isEmpty)

  -- Refusals: a client that did not offer post_handshake_auth cannot be asked,
  -- and one that receives an unsolicited request fails with unexpected_message.
  let (quiet, quietServer) ← connect { clientConfig with postHandshakeAuth := false } serverConfig
  match Server.requestClientCertificate quietServer "q".toUTF8 with
  | .error (.invalidConfig _) => pure ()
  | _ => throw (IO.userError "server asked a client that did not offer post_handshake_auth")
  let forced ← get (Server.requestClientCertificate
    { quietServer with clientOffersPostHandshakeAuth := true } "q".toUTF8)
  match Client.feed quiet forced.wireBytes with
  | .error error =>
      expect "unsolicited CertificateRequest alert" (error.fatalAlertDescription? == some 10)
  | .ok _ => throw (IO.userError "client answered a CertificateRequest it did not invite")
  match Server.requestClientCertificate { server with postHandshakeAuth := none } "z".toUTF8 with
  | .error (.invalidConfig _) => pure ()
  | _ => throw (IO.userError "server asked without a validation policy")

  IO.println "TLS post-handshake authentication regression passed"
