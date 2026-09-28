module

public import HaclStar.Curve25519
public import HaclStar.Hmac
public import HaclStar.P256
public import HaclStar.Sha256
public import Tls.Handshake
public import Tls.Identity
public import Tls.Record
public import TLS13.KeySchedule
public import TLS13.X509

public section

namespace Tls
namespace Client

/-!
A minimal, pure TLS 1.3 client handshake and record machine.

The engine deliberately performs no I/O and obtains no entropy itself. A
caller supplies the ClientHello random, legacy session id, and ephemeral
private scalars to `start`, writes the returned `wireBytes`, and subsequently
passes transport chunks to `feed`. Every server CertificateVerify is checked
cryptographically against the leaf certificate before the handshake can
complete. Certificate-chain and hostname validation remain separate policy
steps for verification modes.
-/

/-- Fresh values and policy used to construct a TLS connection. The X25519
and optional P-256 scalars must be independently generated for this connection
and must never be reused across connections; the pure API cannot enforce that
RFC 9846 §4.3.8 caller obligation. -/
structure PeerAuthPolicy where
  trustStore : TLS13.X509.Chain.TrustStore
  now : Int
  hostname : String
  requireExplicitPurpose : Bool := false
  deriving Inhabited

/-- A session ticket, as the client keeps it (RFC 9846 §4.6.1): the opaque
ticket the server issued, which is the PSK identity, the PSK it stands for, and
what the client needs to offer it later. -/
structure Ticket where
  identity : ByteArray
  psk : ByteArray
  ageAdd : UInt32
  /-- Seconds from receipt that the server will accept the ticket. -/
  lifetime : UInt32
  /-- The server's max_early_data_size for this ticket, 0 when absent. -/
  maxEarlyData : UInt32 := 0
  deriving Inhabited

structure Config where
  clientRandom : ByteArray
  x25519Private : ByteArray
  /-- An independently generated, connection-unique P-256 private scalar. When
  present, the ClientHello sends both X25519 and P-256 shares so pre-18
  PostgreSQL defaults need no HRR. -/
  p256Private : Option ByteArray := none
  /-- With `p256Private`, send the P-256 key share in the first ClientHello.
  When false, P-256 is only listed in supported_groups: a server that prefers
  it asks for the share with a HelloRetryRequest, and the second ClientHello
  carries it (RFC 9846 §4.1.4). -/
  p256FirstFlightShare : Bool := true
  legacySessionId : ByteArray := ByteArray.empty
  serverName : Option String := none
  /-- ALPN protocols to offer, in preference order (empty omits ALPN). -/
  alpnProtocols : Array String := #[]
  /-- Optional immutable client credentials; sent only after CertificateRequest.
  Capture an IdentityStore snapshot once before `start` to support rotation. -/
  identity : Option Identity := none
  /-- Required with client credentials: verify the server before disclosing a
  client certificate. Also usable without mTLS for in-engine verification. -/
  peerAuth : Option PeerAuthPolicy := none
  /-- Offer this ticket to resume (RFC 9846 §2.2, psk_dhe_ke). A server that
  accepts it authenticates with the PSK and sends no certificate; one that does
  not runs a full handshake, verified as usual. -/
  resumption : Option Ticket := none
  /-- Milliseconds since `resumption` was received, for its obfuscated age. -/
  ticketAgeMs : Nat := 0
  deriving Inhabited

/-- Strict server-handshake ordering; CertificateRequest is consumed at the
start of waitingCertificate without introducing an additional record epoch. -/
inductive Phase where
  | waitingServerHello
  | waitingEncryptedExtensions
  | waitingCertificate
  | waitingCertificateVerify
  | waitingServerFinished
  | connected
  deriving Repr, BEq, DecidableEq, Inhabited

namespace Phase

def render : Phase → String
  | .waitingServerHello => "ServerHello"
  | .waitingEncryptedExtensions => "EncryptedExtensions"
  | .waitingCertificate => "Certificate"
  | .waitingCertificateVerify => "CertificateVerify"
  | .waitingServerFinished => "Finished"
  | .connected => "post-handshake message"

end Phase

/-- Errors are protocol-fatal: the caller must discard the state supplied to
the operation that returned the error. -/
inductive Error where
  | invalidEntropy (field : String) (expected actual : Nat)
  | invalidPrivateKey (group : Handshake.NamedGroup)
  | handshakeCodec (message : String)
  | recordLayer (error : Record.Error)
  | keyExchangeFailed
  | unexpectedRecord (phase : Phase) (contentType : Record.ContentType)
  | unexpectedHandshake (phase : Phase) (actual : UInt8)
  | invalidCompatibilityChangeCipherSpec
  | interleavedHandshake
  | invalidAlertLength (actual : Nat)
  | invalidAlertLevel (actual : UInt8)
  | peerAlert (level description : UInt8)
  | peerClosedDuringHandshake
  | badCertificate (message : String)
  | illegalParameter (message : String)
  | certificateVerifySchemeMismatch (algorithm : UInt16)
  | certificateVerifyFailed
  | finishedMismatch
  | trailingHandshakeAfterFinished
  | notConnected (phase : Phase)
  | connectionClosed
  | keyUpdateLimit
  | unsupportedExtension (extensionType : UInt16)
  | invalidExporterRequest (message : String)
  | internalState (message : String)
  deriving Repr, Inhabited

private def contentTypeName : Record.ContentType → String
  | .changeCipherSpec => "change_cipher_spec"
  | .alert => "alert"
  | .handshake => "handshake"
  | .applicationData => "application_data"

namespace Error

def render : Error → String
  | .invalidEntropy field expected actual =>
      s!"TLS {field} must be {expected} bytes, got {actual}"
  | .invalidPrivateKey group =>
      s!"TLS {repr group} private scalar is outside the valid group order"
  | .handshakeCodec message => s!"TLS handshake codec: {message}"
  | .recordLayer error => s!"TLS record layer: {error}"
  | .keyExchangeFailed => "TLS key exchange rejected the server public key"
  | .unexpectedRecord phase contentType =>
      s!"unexpected TLS {contentTypeName contentType} record while waiting for {phase.render}"
  | .unexpectedHandshake phase actual =>
      s!"unexpected TLS handshake message {actual} while waiting for {phase.render}"
  | .invalidCompatibilityChangeCipherSpec =>
      "invalid TLS 1.3 compatibility ChangeCipherSpec"
  | .interleavedHandshake =>
      "TLS handshake fragments were interleaved with another content type"
  | .invalidAlertLength actual =>
      s!"TLS alert payload must be exactly two bytes, got {actual}"
  | .invalidAlertLevel actual => s!"invalid TLS alert level {actual}"
  | .peerAlert level description =>
      s!"TLS peer sent alert level {level}, description {description}"
  | .peerClosedDuringHandshake => "TLS peer sent close_notify during the handshake"
  | .badCertificate message => s!"TLS bad_certificate: {message}"
  | .illegalParameter message => s!"TLS illegal_parameter: {message}"
  | .certificateVerifySchemeMismatch algorithm =>
      s!"TLS illegal_parameter: CertificateVerify scheme {algorithm} \
        is inconsistent with the leaf public key"
  | .certificateVerifyFailed =>
      "TLS decrypt_error: server CertificateVerify signature verification failed"
  | .finishedMismatch => "TLS server Finished verification failed"
  | .trailingHandshakeAfterFinished =>
      "TLS server Finished shared a record with data protected under different keys"
  | .notConnected phase =>
      s!"TLS connection is not ready for application data (waiting for {phase.render})"
  | .connectionClosed => "TLS connection is closed"
  | .keyUpdateLimit => "TLS KeyUpdate limit of 2^48-1 sending epochs reached"
  | .unsupportedExtension extensionType =>
      s!"TLS server sent extension {extensionType} the client did not offer"
  | .invalidExporterRequest message => s!"TLS exporter: {message}"
  | .internalState message => s!"invalid internal TLS client state: {message}"

/-- Fatal TLS alert description associated with a locally detected handshake
failure. The I/O shell seals and sends this alert before discarding the
connection when handshake write keys are available. -/
def fatalAlertDescription? : Error → Option UInt8
  | .badCertificate _ => some 42
  | .illegalParameter _ => some 47
  | .certificateVerifySchemeMismatch _ => some 47
  | .certificateVerifyFailed => some 51
  | .finishedMismatch => some 51
  | .handshakeCodec _ => some 50
  | .unexpectedHandshake _ _ => some 10
  | .unexpectedRecord _ _ => some 10
  | .interleavedHandshake => some 10
  | .trailingHandshakeAfterFinished => some 10
  | .invalidAlertLength 0 => some 10
  | .invalidAlertLength _ => some 50
  | .keyExchangeFailed => some 47
  | .unsupportedExtension _ => some 110
  | _ => none

end Error

instance : ToString Error := ⟨Error.render⟩

/-- RFC 9846 §4.7.3's upper bound on sending traffic-secret generations.
Once this many KeyUpdates have been sent, requests for another reciprocal
update are still honored on the read side but no response is emitted. -/
def maxSendingKeyUpdates : Nat := (2 ^ 48) - 1

/--
Pure connection state. Traffic keys and ephemeral private values are kept
inside the state but the structure intentionally has no `Repr` instance, so
ordinary debugging cannot accidentally print them.
-/
structure State where
  phase : Phase
  decoder : Record.Decoder := {}
  handshakeBuffered : ByteArray := ByteArray.empty
  transcript : ByteArray := ByteArray.empty
  x25519Private : ByteArray
  p256Private : Option ByteArray := none
  legacySessionId : ByteArray
  /-- Exact cipher suites advertised by this connection's ClientHello. The
  ServerHello selection is checked against this list rather than against a
  hard-coded singleton, so adding suites does not weaken negotiation checks. -/
  offeredCipherSuites : Array UInt16 := #[]
  /-- Key-share groups actually sent in this connection's ClientHello. After a
  HelloRetryRequest, exactly the group it selected. -/
  offeredKeyShareGroups : Array Handshake.NamedGroup := #[]
  /-- Groups listed in this connection's supported_groups. -/
  supportedGroups : Array Handshake.NamedGroup := #[]
  /-- The ClientHello's public parameters, kept to build the second ClientHello
  a HelloRetryRequest asks for. -/
  helloConfig : Handshake.ClientHelloConfig := default
  /-- A HelloRetryRequest has been answered; RFC 9846 §4.1.4 forbids a second. -/
  retried : Bool := false
  /-- The PSK this connection's ClientHello offers, if it resumes. -/
  offeredPsk? : Option ByteArray := none
  /-- The server accepted the offered PSK: no certificate is expected. -/
  resumed : Bool := false
  /-- RFC 9846 §7.1 `resumption_master_secret`, once connected. -/
  resumptionMasterSecret? : Option ByteArray := none
  /-- Tickets the server has sent on this connection, oldest first. -/
  tickets : Array Ticket := #[]
  /-- ALPN protocol IDs advertised by this connection's ClientHello. -/
  offeredAlpnProtocols : Array String := #[]
  identity : Option Identity := none
  peerAuth : Option PeerAuthPolicy := none
  certificateRequested : Bool := false
  clientSignaturePermitted : Bool := false
  handshakeSecret? : Option ByteArray := none
  clientHandshakeTrafficSecret? : Option ByteArray := none
  serverHandshakeTrafficSecret? : Option ByteArray := none
  /-- RFC 9846 §7.1 `exporter_master_secret`, installed on reaching `connected`
  and kept for `exportKeyingMaterial`. -/
  exporterMasterSecret? : Option ByteArray := none
  readKeys? : Option Record.TrafficKeys := none
  writeKeys? : Option Record.TrafficKeys := none
  /-- Number of application write-key generations installed by KeyUpdate.
  The initial application traffic secret is generation zero. -/
  sendingKeyUpdates : Nat := 0
  leafCertificate? : Option ByteArray := none
  /-- The peer's Certificate-list entries, strict-parsed once from the exact
  handshake bytes and retained in wire order (leaf first). Post-handshake
  verification policy consumes these values without decoding DER again. -/
  peerCertificates : Array TLS13.X509.Certificate := #[]
  leafPublicKey? : Option TLS13.X509.SubjectPublicKeyInfo := none
  /-- The ALPN protocol the server selected, once EncryptedExtensions is seen. -/
  alpnSelected : Option String := none
  localClosed : Bool := false
  peerClosed : Bool := false
  deriving Inhabited

namespace State

def connected (state : State) : Bool :=
  state.phase == .connected

/-- Both TLS write directions have exchanged `close_notify`. -/
def closed (state : State) : Bool :=
  state.localClosed && state.peerClosed

end State

/-- Bytes and state produced by every engine operation. -/
structure Output where
  state : State
  wireBytes : ByteArray := ByteArray.empty
  plaintext : ByteArray := ByteArray.empty
  deriving Inhabited

/-- A failed incremental feed together with the latest state completed before
the failing record. Keeping the state lets an I/O shell use the correct write
traffic epoch for a fatal alert, even when one transport chunk coalesces
ServerHello with the encrypted server flight. The decoder may already have
consumed the failing record, so this state is only for sealing an alert and
must not be resumed. -/
structure Failure where
  state : State
  error : Error

private def liftHandshake {α : Type} (result : Except String α) : Except Error α :=
  match result with
  | .ok value => .ok value
  | .error message => .error (.handshakeCodec message)

private def liftRecord {α : Type} (result : Except Record.Error α) : Except Error α :=
  match result with
  | .ok value => .ok value
  | .error error => .error (.recordLayer error)

private def requireReadKeys (state : State) : Except Error Record.TrafficKeys :=
  match state.readKeys? with
  | some keys => pure keys
  | none => throw (.internalState "missing read traffic keys")

private def requireWriteKeys (state : State) : Except Error Record.TrafficKeys :=
  match state.writeKeys? with
  | some keys => pure keys
  | none => throw (.internalState "missing write traffic keys")

private def requireHandshakeSecret (state : State) : Except Error ByteArray :=
  match state.handshakeSecret? with
  | some secret => pure secret
  | none => throw (.internalState "missing handshake secret")

private def requireClientHandshakeTrafficSecret (state : State) : Except Error ByteArray :=
  match state.clientHandshakeTrafficSecret? with
  | some secret => pure secret
  | none => throw (.internalState "missing client handshake traffic secret")

private def requireServerHandshakeTrafficSecret (state : State) : Except Error ByteArray :=
  match state.serverHandshakeTrafficSecret? with
  | some secret => pure secret
  | none => throw (.internalState "missing server handshake traffic secret")

private def requireLeafPublicKey (state : State) :
    Except Error TLS13.X509.SubjectPublicKeyInfo :=
  match state.leafPublicKey? with
  | some publicKey => pure publicKey
  | none => throw (.internalState "missing parsed leaf public key")

private def decodeCertificate (der : ByteArray) :
    Except Error TLS13.X509.Certificate :=
  match TLS13.X509.Certificate.decode der with
  | .ok certificate => pure certificate
  | .error message => throw (.badCertificate message)

private def certificateVerifyScheme? (algorithm : UInt16) :
    Option TLS13.X509.Signature.CertificateVerifyScheme :=
  if algorithm == Handshake.ecdsaSecp256r1Sha256 then
    some .ecdsaSecp256r1Sha256
  else if algorithm == Handshake.ed25519 then
    some .ed25519
  else if algorithm == Handshake.rsaPssRsaeSha256 then
    some .rsaPssRsaeSha256
  else if algorithm == Handshake.rsaPssPssSha256 then
    some .rsaPssPssSha256
  else
    none

private theorem liftHandshake_ok {α : Type} {result : Except String α}
    {value : α} (h : liftHandshake result = .ok value) : result = .ok value := by
  unfold liftHandshake at h
  cases result with
  | error e => simp at h
  | ok b => simpa [Except.mapError] using h

/-- Return one complete framed handshake message without treating an
incomplete prefix as a codec error. The reassembly itself, and its laws, live
in `Tls.Handshake`; this only adapts the error type. -/
private def takeHandshake? (buffered : ByteArray) :
    Except Error (Option (Handshake.Message × ByteArray)) :=
  liftHandshake (Handshake.takeMessage? buffered)

/-- A successful `takeHandshake?` consumes the four-byte message header plus
the body, strictly shrinking the buffer. -/
private theorem takeHandshake?_size {buffered rest : ByteArray}
    {message : Handshake.Message}
    (h : takeHandshake? buffered = .ok (some (message, rest))) :
    rest.size < buffered.size :=
  Handshake.takeMessage?_size (liftHandshake_ok h)

/-- A successful `takeHandshake?` conserves bytes: the decoded message's
retained exact encoding followed by the returned remainder is the input
buffer — the handshake-layer mirror of the record-framing conservation law
(`Tls.Record.Laws.decodeStep_conservation`). -/
private theorem takeHandshake?_conservation {buffered rest : ByteArray}
    {message : Handshake.Message}
    (h : takeHandshake? buffered = .ok (some (message, rest))) :
    message.encoded ++ rest = buffered :=
  Handshake.takeMessage?_conservation (liftHandshake_ok h)

def constantTimeEq (left right : ByteArray) : Bool :=
  if left.size != right.size then
    false
  else
    Id.run do
      let mut different : UInt8 := 0
      for i in [0:left.size] do
        different := different ||| (left.get! i ^^^ right.get! i)
      return different == 0

def finishedVerifyData (trafficSecret transcriptHash : ByteArray) : ByteArray :=
  let finishedKey := TLS13.KeySchedule.expandLabel trafficSecret "finished"
    ByteArray.empty TLS13.KeySchedule.hashLen
  HaclStar.hmacSha256 finishedKey transcriptHash

private def emptyTranscriptHash : ByteArray :=
  HaclStar.sha256 ByteArray.empty

private def checkIdentity (config : Config) : Except Error Unit := do
  if let some identity := config.identity then
    unless identity.purpose == .clientAuth do
      throw (.badCertificate "client identity has the wrong certificate purpose")
    unless config.peerAuth.isSome do
      throw (.badCertificate "client identity requires pre-disclosure server verification")

/-- Fill in the PSK binder of a ClientHello that offers `psk` (RFC 9846
§4.2.11.2): the HMAC, under the finished key of `Derive-Secret(Early Secret,
"res binder", "")`, of the transcript before this ClientHello followed by the
ClientHello truncated before its binders. -/
def bindPsk (psk? : Option ByteArray) (beforeHello : ByteArray)
    (hello : Handshake.Message) : Handshake.Message :=
  match psk? with
  | none => hello
  | some psk =>
    let binderKey := TLS13.KeySchedule.binderKey (TLS13.KeySchedule.earlySecret psk)
      emptyTranscriptHash
    Handshake.withPskBinder hello (finishedVerifyData binderKey (HaclStar.sha256
      (beforeHello ++ Handshake.truncatedClientHello hello.encoded
        Handshake.clientBindersLength)))

/-- Create ClientHello and initial state from fresh caller-provided entropy.
Credentials require an explicit server-verification policy. -/
def start (config : Config) : Except Error Output := do
  checkIdentity config
  unless config.clientRandom.size == 32 do
    throw (.invalidEntropy "ClientHello random" 32 config.clientRandom.size)
  unless config.x25519Private.size == 32 do
    throw (.invalidEntropy "X25519 private key" 32 config.x25519Private.size)
  if let some privateKey := config.p256Private then
    unless privateKey.size == 32 do
      throw (.invalidEntropy "P-256 private key" 32 privateKey.size)
  if config.legacySessionId.size > 32 then
    throw (.invalidEntropy "legacy session id (maximum)" 32 config.legacySessionId.size)

  let publicKey := HaclStar.X25519.base config.x25519Private
  unless publicKey.size == 32 do
    throw (.internalState s!"X25519 returned a {publicKey.size}-byte public key")
  let p256PublicKey ← match config.p256Private with
    | none => pure none
    | some privateKey =>
      let some publicKey := HaclStar.P256.publicKey privateKey
        | throw (.invalidPrivateKey .secp256r1)
      unless publicKey.size == 65 && publicKey.get! 0 == 4 do
        throw (.internalState "P-256 returned a malformed public key")
      pure (some publicKey)
  let helloConfig : Handshake.ClientHelloConfig := {
    random := config.clientRandom
    x25519PublicKey := publicKey
    p256PublicKey := if config.p256FirstFlightShare then p256PublicKey else none
    serverName := config.serverName
    legacySessionId := config.legacySessionId
    alpnProtocols := config.alpnProtocols
    offerP256 := p256PublicKey.isSome
    pskOffer := config.resumption.map fun ticket => {
      identity := ticket.identity
      obfuscatedTicketAge :=
        UInt32.ofNat ((config.ticketAgeMs + ticket.ageAdd.toNat) % 4294967296)
    }
  }
  let hello ← liftHandshake <| Handshake.encodeClientHello helloConfig
  let hello := bindPsk (config.resumption.map (·.psk)) ByteArray.empty hello
  let wireBytes ← liftRecord <| Record.encodePlaintext .handshake hello.encoded
  let state : State := {
    phase := .waitingServerHello
    transcript := hello.encoded
    x25519Private := config.x25519Private
    p256Private := config.p256Private
    legacySessionId := config.legacySessionId
    offeredCipherSuites := #[Handshake.tlsChaCha20Poly1305Sha256]
    offeredKeyShareGroups :=
      if config.p256Private.isSome && config.p256FirstFlightShare then
        #[.x25519, .secp256r1]
      else
        #[.x25519]
    supportedGroups :=
      if config.p256Private.isSome then #[.x25519, .secp256r1] else #[.x25519]
    helloConfig
    offeredPsk? := config.resumption.map (·.psk)
    offeredAlpnProtocols := config.alpnProtocols
    identity := config.identity
    peerAuth := config.peerAuth
  }
  pure { state, wireBytes }

/-- The ServerHello checks that touch no key state: the session-id echo, and the
requirement that the selected cipher suite and key-share group are ones this
connection's ClientHello actually offered. Factored out of `acceptServerHello`
so that function stays a short chain of binds the engine laws can walk. -/
private def checkServerHello (state : State) (hello : Handshake.ServerHello) :
    Except Error (Option ByteArray) := do
  unless hello.legacySessionIdEcho == state.legacySessionId do
    throw (.illegalParameter
      "ServerHello legacy_session_id_echo does not match ClientHello")
  unless state.offeredCipherSuites.contains hello.cipherSuite do
    throw (.illegalParameter
      s!"server selected cipher suite {hello.cipherSuite} that the client did not offer")
  unless state.offeredKeyShareGroups.contains hello.selectedGroup do
    throw (.illegalParameter
      s!"server selected key-share group {hello.selectedGroup.toUInt16} \
        that the client did not offer")
  -- RFC 9846 §4.2.11: a selected PSK must be the one this ClientHello offered.
  match ← liftHandshake hello.selectedPsk? with
  | none => pure none
  | some index =>
    let some psk := state.offeredPsk?
      | throw (.illegalParameter "server selected a PSK the client did not offer")
    unless index == 0 do
      throw (.illegalParameter s!"server selected PSK identity {index} of 1")
    pure (some psk)

/-- Accept the ServerHello: check the echoed session id and the negotiated
parameters, complete the key exchange, and install the RFC 8446 §7.1 handshake
traffic epochs over the ClientHello…ServerHello transcript. Public (but not
`@[expose]`d) so `Tls.Client.Laws` can state its transcript and key-schedule
laws as public theorems. -/
def acceptServerHello (state : State) (message : Handshake.Message) :
    Except Error State := do
  unless state.phase == .waitingServerHello do
    throw (.unexpectedHandshake state.phase message.msgType)
  let hello ← liftHandshake (Handshake.parseServerHello message)
  let psk ← checkServerHello state hello
  let sharedSecret ← match hello.selectedGroup with
    | .x25519 =>
      let some sharedSecret :=
          HaclStar.X25519.ecdh state.x25519Private hello.keyExchange
        | throw .keyExchangeFailed
      pure sharedSecret
    | .secp256r1 =>
      let some privateKey := state.p256Private
        | throw (.illegalParameter "server selected P-256 without a client key share")
      let some sharedSecret := HaclStar.P256.ecdh privateKey hello.keyExchange
        | throw .keyExchangeFailed
      pure sharedSecret
  unless sharedSecret.size == TLS13.KeySchedule.hashLen do
    throw (.internalState
      s!"ECDHE returned a {sharedSecret.size}-byte shared secret")

  let earlySecret := TLS13.KeySchedule.earlySecret (psk.getD TLS13.KeySchedule.zeros)
  let handshakeSecret :=
    TLS13.KeySchedule.handshakeSecret earlySecret sharedSecret emptyTranscriptHash
  let transcript := state.transcript ++ message.encoded
  let transcriptHash := HaclStar.sha256 transcript
  let clientTrafficSecret :=
    TLS13.KeySchedule.deriveSecret handshakeSecret "c hs traffic" transcriptHash
  let serverTrafficSecret :=
    TLS13.KeySchedule.deriveSecret handshakeSecret "s hs traffic" transcriptHash
  let writeKeys ← liftRecord (Record.deriveTrafficKeys clientTrafficSecret)
  let readKeys ← liftRecord (Record.deriveTrafficKeys serverTrafficSecret)
  pure {
    state with
    phase := .waitingEncryptedExtensions
    handshakeBuffered := ByteArray.empty
    transcript
    resumed := psk.isSome
    handshakeSecret? := some handshakeSecret
    clientHandshakeTrafficSecret? := some clientTrafficSecret
    serverHandshakeTrafficSecret? := some serverTrafficSecret
    readKeys? := some readKeys
    writeKeys? := some writeKeys
  }

/-- The RFC 9846 §4.1.4 checks on a HelloRetryRequest that touch no state: at
most one per connection; the session id echoed; a cipher suite this ClientHello
offered; a group it listed but sent no share for (so the retry changes the
ClientHello); and no extension beyond supported_versions, key_share and a
well-formed cookie. -/
private def checkHelloRetryRequest (state : State)
    (retry : Handshake.HelloRetryRequest) : Except Error Unit := do
  if state.retried then
    throw (.unexpectedHandshake .waitingServerHello Handshake.serverHelloType)
  unless retry.legacySessionIdEcho == state.legacySessionId do
    throw (.illegalParameter
      "HelloRetryRequest legacy_session_id_echo does not match ClientHello")
  unless state.offeredCipherSuites.contains retry.cipherSuite do
    throw (.illegalParameter
      s!"HelloRetryRequest selected cipher suite {retry.cipherSuite} that the client did not offer")
  unless state.supportedGroups.contains retry.selectedGroup do
    throw (.illegalParameter
      s!"HelloRetryRequest selected group {retry.selectedGroup.toUInt16} the client did not list")
  if state.offeredKeyShareGroups.contains retry.selectedGroup then
    throw (.illegalParameter
      s!"HelloRetryRequest selected group {retry.selectedGroup.toUInt16}, \
        which the ClientHello already carried a share for")
  for extension in retry.extensions do
    let t := extension.extensionType
    unless t == Handshake.supportedVersionsExtension || t == Handshake.keyShareExtension
        || t == Handshake.cookieExtension do
      throw (.unsupportedExtension t)
    if t == Handshake.cookieExtension then
      -- struct { opaque cookie<1..2^16-1>; }
      let body := extension.data
      unless body.size ≥ 3 &&
          (body.get! 0).toNat * 256 + (body.get! 1).toNat + 2 == body.size do
        throw (.handshakeCodec "malformed HelloRetryRequest cookie")

/-- The P-256 share for a second ClientHello, when the HelloRetryRequest
selected P-256; `checkHelloRetryRequest` has already required that no P-256
share was sent, so this key's public value is new on the wire. -/
private def retryP256PublicKey (state : State) :
    Handshake.NamedGroup → Except Error (Option ByteArray)
  | .x25519 => pure none
  | .secp256r1 => do
    let some privateKey := state.p256Private
      | throw (.illegalParameter "HelloRetryRequest selected P-256 without a client key")
    let some publicKey := HaclStar.P256.publicKey privateKey
      | throw (.invalidPrivateKey .secp256r1)
    pure (some publicKey)

/-- Answer a HelloRetryRequest (RFC 9846 §4.1.4): send a second ClientHello
that is the first with a single key share for the selected group and the
cookie echoed, and replace the first ClientHello in the transcript with its
synthetic `message_hash`. No keys are derived. The ServerHello that follows
must select this cipher suite and this group, which `checkServerHello` then
enforces, because they become the only ones offered. -/
def acceptHelloRetryRequest (state : State) (message : Handshake.Message) :
    Except Error (State × ByteArray) := do
  unless state.phase == .waitingServerHello do
    throw (.unexpectedHandshake state.phase message.msgType)
  let retry ← liftHandshake (Handshake.parseHelloRetryRequest message)
  checkHelloRetryRequest state retry
  let p256PublicKey ← retryP256PublicKey state retry.selectedGroup
  let cookie := (retry.extensions.find?
    (·.extensionType == Handshake.cookieExtension)).map (·.data)
  let secondHello ← liftHandshake <| Handshake.encodeClientHello {
    state.helloConfig with
    sendX25519Share := retry.selectedGroup == .x25519
    p256PublicKey
    cookie
  }
  let messageHash ← liftHandshake
    (Handshake.frame Handshake.messageHashType (HaclStar.sha256 state.transcript))
  -- The binder of the second ClientHello covers message_hash and the
  -- HelloRetryRequest too (RFC 9846 §4.2.11.2).
  let secondHello := bindPsk state.offeredPsk? (messageHash.encoded ++ message.encoded)
    secondHello
  let wireBytes ← liftRecord (Record.encodePlaintext .handshake secondHello.encoded)
  pure ({
    state with
    handshakeBuffered := ByteArray.empty
    transcript := messageHash.encoded ++ message.encoded ++ secondHello.encoded
    offeredCipherSuites := #[retry.cipherSuite]
    offeredKeyShareGroups := #[retry.selectedGroup]
    retried := true
  }, wireBytes)

private def feedPlaintextHandshake (state : State) (fragment : ByteArray) :
    Except Error (State × ByteArray) := do
  if fragment.isEmpty then
    throw (.unexpectedRecord state.phase .handshake)
  let buffered := state.handshakeBuffered ++ fragment
  let some (message, rest) ← takeHandshake? buffered
    | pure ({ state with handshakeBuffered := buffered }, ByteArray.empty)
  unless rest.isEmpty do
    throw (.unexpectedHandshake .waitingServerHello (rest.get! 0))
  if Handshake.isHelloRetryRequest message then
    acceptHelloRetryRequest { state with handshakeBuffered := ByteArray.empty } message
  else
    let state ← acceptServerHello { state with handshakeBuffered := ByteArray.empty } message
    pure (state, ByteArray.empty)

private def appendTranscript (state : State) (message : Handshake.Message) : State :=
  { state with transcript := state.transcript ++ message.encoded }

/-- Client authentication is signed only after the server Finished verifies.
The returned bytes are part of the client Finished transcript, never the
application-secret transcript (which ends at the server Finished). -/
private def clientAuthentication (state : State) (transcript : ByteArray) :
    Except Error ByteArray := do
  if !state.certificateRequested then
    return ByteArray.empty
  let identity := if state.clientSignaturePermitted then state.identity else none
  let certificate ← liftHandshake (Handshake.encodeClientCertificate
    (identity.map (·.certificateChain) |>.getD #[]))
  match identity with
  | none => pure certificate.encoded
  | some identity =>
    let content ← liftHandshake (TLS13.X509.Signature.clientCertificateVerifyContent
      (HaclStar.sha256 (transcript ++ certificate.encoded)))
    let signature := HaclStar.Signature.ed25519Sign identity.signingKey content
    let verify ← liftHandshake (Handshake.encodeCertificateVerify Handshake.ed25519 signature)
    pure (certificate.encoded ++ verify.encoded)

private def verifyServerIdentity (state : State) : Except Error Unit := do
  -- A resumed session was authenticated when its ticket was issued.
  if state.resumed then
    return
  if let some policy := state.peerAuth then
    let some leaf := state.peerCertificates[0]?
      | throw (.badCertificate "missing peer certificate")
    let verified ← match TLS13.X509.Chain.validate policy.now leaf
        (state.peerCertificates.extract 1 state.peerCertificates.size) policy.trustStore
        10 128 .serverAuth policy.requireExplicitPurpose with
      | .ok verified => pure verified
      | .error _ => throw (.badCertificate "server trust or purpose verification failed")
    match TLS13.X509.Hostname.verifyHostname policy.hostname verified.leaf with
    | .ok () => pure ()
    | .error _ => throw (.badCertificate "server hostname verification failed")

private def sealClientFlight (keys : Record.TrafficKeys) (flight : ByteArray)
    (offset : Nat := 0) (wire : ByteArray := ByteArray.empty) :
    Except Error (Record.TrafficKeys × ByteArray) :=
  if flight.size ≤ offset then .ok (keys, wire)
  else
    let stop := min flight.size (offset + 16384)
    match liftRecord (Record.«seal» keys .handshake (flight.extract offset stop)) with
    | .error e => .error e
    | .ok (keys, bytes) => sealClientFlight keys flight stop (wire ++ bytes)
  termination_by flight.size - offset
  decreasing_by omega

def completeServerHandshake (state : State) (message : Handshake.Message) :
    Except Error (State × ByteArray) := do
  let finished ← liftHandshake (Handshake.parseFinished message)
  let serverTrafficSecret ← requireServerHandshakeTrafficSecret state
  let expected := finishedVerifyData serverTrafficSecret (HaclStar.sha256 state.transcript)
  unless constantTimeEq expected finished.verifyData do
    throw .finishedMismatch

  let transcriptThroughServerFinished := state.transcript ++ message.encoded
  let transcriptHash := HaclStar.sha256 transcriptThroughServerFinished
  let handshakeSecret ← requireHandshakeSecret state
  let masterSecret := TLS13.KeySchedule.masterSecret handshakeSecret emptyTranscriptHash
  let clientApplicationSecret :=
    TLS13.KeySchedule.deriveSecret masterSecret "c ap traffic" transcriptHash
  let serverApplicationSecret :=
    TLS13.KeySchedule.deriveSecret masterSecret "s ap traffic" transcriptHash
  let exporterMasterSecret :=
    TLS13.KeySchedule.deriveSecret masterSecret "exp master" transcriptHash
  let clientApplicationKeys ← liftRecord (Record.deriveTrafficKeys clientApplicationSecret)
  let serverApplicationKeys ← liftRecord (Record.deriveTrafficKeys serverApplicationSecret)

  let clientHandshakeSecret ← requireClientHandshakeTrafficSecret state
  verifyServerIdentity state
  let authentication ← clientAuthentication state transcriptThroughServerFinished
  let clientVerifyData := finishedVerifyData clientHandshakeSecret
    (HaclStar.sha256 (transcriptThroughServerFinished ++ authentication))
  let clientFinished ← liftHandshake (Handshake.encodeFinished clientVerifyData)
  let handshakeWriteKeys ← requireWriteKeys state
  let (_, finishedWireBytes) ← sealClientFlight handshakeWriteKeys
    (authentication ++ clientFinished.encoded)
  -- A nonempty legacy session id opts into RFC 8446 appendix D.4's
  -- middlebox-compatibility mode.  The dummy CCS is deliberately plaintext
  -- and immediately precedes the client's encrypted second flight.
  let compatibilityWireBytes ←
    if state.legacySessionId.isEmpty then
      pure ByteArray.empty
    else
      liftRecord (Record.encodePlaintext .changeCipherSpec (ByteArray.empty.push 1))
  let wireBytes := compatibilityWireBytes ++ finishedWireBytes
  -- RFC 9846 §7.1: resumption_master_secret binds ClientHello…client Finished.
  let resumptionMasterSecret := TLS13.KeySchedule.deriveSecret masterSecret "res master"
    (HaclStar.sha256 (transcriptThroughServerFinished ++ authentication ++
      clientFinished.encoded))
  pure ({
    state with
    phase := .connected
    handshakeBuffered := ByteArray.empty
    -- The application traffic secrets are now independent of these handshake
    -- inputs. Do not retain obsolete private scalars, handshake traffic
    -- secrets, or a potentially large certificate transcript for the life of
    -- the PostgreSQL connection.
    transcript := ByteArray.empty
    x25519Private := ByteArray.empty
    p256Private := none
    legacySessionId := ByteArray.empty
    offeredCipherSuites := #[]
    offeredKeyShareGroups := #[]
    offeredAlpnProtocols := #[]
    handshakeSecret? := none
    clientHandshakeTrafficSecret? := none
    serverHandshakeTrafficSecret? := none
    identity := none
    peerAuth := none
    certificateRequested := false
    clientSignaturePermitted := false
    readKeys? := some serverApplicationKeys
    writeKeys? := some clientApplicationKeys
    exporterMasterSecret? := some exporterMasterSecret
    resumptionMasterSecret? := some resumptionMasterSecret
    offeredPsk? := none
    sendingKeyUpdates := 0
  }, wireBytes)

/-- Seal a fatal, level-2 TLS alert under the current write traffic keys.
Callers must discard the connection after sending the returned bytes. -/
def sealFatalAlert (state : State) (description : UInt8) :
    Except Error Output := do
  if state.localClosed then
    throw .connectionClosed
  let writeKeys ← requireWriteKeys state
  let fragment := ByteArray.mk #[2, description]
  let (writeKeys, wireBytes) ←
    liftRecord (Record.«seal» writeKeys .alert fragment)
  pure {
    state := { state with writeKeys? := some writeKeys, localClosed := true }
    wireBytes
  }

/-- RFC 9846 §7.5 keying material exporter, with RFC 5705's interface:
`TLS-Exporter(label, context, length)` from this connection's
`exporter_master_secret`. TLS 1.3 makes an empty context the same as no context.
Available once the handshake completes; it reads the state and changes nothing. -/
def exportKeyingMaterial (state : State) (label context : ByteArray) (length : Nat) :
    Except Error ByteArray := do
  unless state.phase == .connected do
    throw (.notConnected state.phase)
  if let some message := TLS13.KeySchedule.exporterRequestError? label length then
    throw (.invalidExporterRequest message)
  let some secret := state.exporterMasterSecret?
    | throw (.internalState "missing exporter master secret")
  pure (TLS13.KeySchedule.exporter secret label emptyTranscriptHash
    (HaclStar.sha256 context) length)

/-- Seal a KeyUpdate under the current write epoch, then move that epoch to the
next traffic secret (RFC 9846 §4.6.3). `request` is `update_not_requested` for a
reply to the peer's request; `updateKeys` sends either kind. At the 2^48-1
sending-epoch limit it sends nothing. -/
private def sendKeyUpdate (state : State)
    (request : Handshake.KeyUpdateRequest := .updateNotRequested) :
    Except Error (State × ByteArray) := do
  if state.sendingKeyUpdates < maxSendingKeyUpdates then
    let message ← liftHandshake <|
      Handshake.encodeKeyUpdate request
    let writeKeys ← requireWriteKeys state
    let (advancedKeys, wireBytes) ←
      liftRecord (Record.«seal» writeKeys .handshake message.encoded)
    let updatedKeys ← liftRecord advancedKeys.update
    pure ({ state with
      writeKeys? := some updatedKeys
      sendingKeyUpdates := state.sendingKeyUpdates + 1
    }, wireBytes)
  else
    pure (state, ByteArray.empty)

/-- Send a KeyUpdate now (RFC 9846 §4.6.3), moving this side's write epoch to
the next traffic secret. With `requestPeer` the peer must answer with its own
KeyUpdate, which `feed` processes like any other. Refused before the handshake
completes, after this side's `close_notify`, and at RFC 9846's 2^48-1 limit on
the epochs one side may send. -/
def updateKeys (state : State) (requestPeer : Bool := false) : Except Error Output := do
  unless state.phase == .connected do
    throw (.notConnected state.phase)
  if state.localClosed then
    throw .connectionClosed
  unless state.sendingKeyUpdates < maxSendingKeyUpdates do
    throw .keyUpdateLimit
  let (state, wireBytes) ←
    sendKeyUpdate state (if requestPeer then .updateRequested else .updateNotRequested)
  pure { state, wireBytes }


private def parseKeyUpdateForClient (message : Handshake.Message) :
    Except Error Handshake.KeyUpdate :=
  if message.msgType == Handshake.keyUpdateType && message.body.size == 1 then
    match Handshake.KeyUpdateRequest.ofUInt8? (message.body.get! 0) with
    | none => .error (.illegalParameter
        s!"invalid KeyUpdate request value {message.body.get! 0}")
    | some _ => liftHandshake (Handshake.parseKeyUpdate message)
  else
    -- Wrong type or body length is a handshake syntax/decode error. Only a
    -- well-framed one-byte request with an unknown value is illegal_parameter.
    liftHandshake (Handshake.parseKeyUpdate message)

def acceptKeyUpdate (state : State) (message : Handshake.Message) :
    Except Error (State × ByteArray) := do
  let update ← parseKeyUpdateForClient message
  let readKeys ← requireReadKeys state
  let updatedReadKeys ← liftRecord readKeys.update
  let state := { state with readKeys? := some updatedReadKeys }
  match update.request with
  | .updateNotRequested => pure (state, ByteArray.empty)
  | .updateRequested =>
      if state.localClosed then
        -- A crossing request advances the read epoch above, but close_notify
        -- promised that this write direction sends no more.
        pure (state, ByteArray.empty)
      else
        sendKeyUpdate state

/-! Reduction lemmas used to prove that key updates and transcript appends
leave the handshake buffer untouched, which bounds the
`processHandshakeBuffer` recursion. -/

private theorem except_bind_ok {ε α β : Type} (a : α) (f : α → Except ε β) :
    (Except.ok a >>= f) = f a := rfl
private theorem except_bind_error {ε α β : Type} (e : ε)
    (f : α → Except ε β) :
    ((Except.error e : Except ε α) >>= f) = Except.error e := rfl
private theorem except_pure {ε α : Type} (a : α) :
    (pure a : Except ε α) = Except.ok a := rfl

private theorem appendTranscript_buffered (state : State)
    (message : Handshake.Message) :
    (appendTranscript state message).handshakeBuffered =
      state.handshakeBuffered := rfl

private theorem sendKeyUpdate_buffered {state next : State}
    {wireBytes : ByteArray}
    {request : Handshake.KeyUpdateRequest} (h : sendKeyUpdate state request = .ok (next, wireBytes)) :
  next.handshakeBuffered = state.handshakeBuffered := by
  unfold sendKeyUpdate at h
  split at h
  case isFalse =>
    cases h
    rfl
  case isTrue =>
    cases h1 : liftHandshake (Handshake.encodeKeyUpdate request) with
    | error e => rw [h1, except_bind_error] at h; cases h
    | ok message =>
        rw [h1, except_bind_ok] at h
        cases h2 : requireWriteKeys state with
        | error e => rw [h2, except_bind_error] at h; cases h
        | ok writeKeys =>
            rw [h2, except_bind_ok] at h
            cases h3 : liftRecord
                (Record.«seal» writeKeys .handshake message.encoded) with
            | error e => rw [h3, except_bind_error] at h; cases h
            | ok sealed =>
                obtain ⟨advancedKeys, sealedBytes⟩ := sealed
                rw [h3, except_bind_ok] at h
                cases h4 : liftRecord advancedKeys.update with
                | error e =>
                    simp only [h4, except_bind_error] at h
                    cases h
                | ok updatedKeys =>
                    simp only [h4, except_bind_ok, except_pure,
                      Except.ok.injEq, Prod.mk.injEq] at h
                    rw [← h.1]

private theorem acceptKeyUpdate_buffered {state next : State}
    {message : Handshake.Message} {wireBytes : ByteArray}
    (h : acceptKeyUpdate state message = .ok (next, wireBytes)) :
  next.handshakeBuffered = state.handshakeBuffered := by
  unfold acceptKeyUpdate at h
  cases h1 : parseKeyUpdateForClient message with
  | error e => rw [h1, except_bind_error] at h; cases h
  | ok update =>
      rw [h1, except_bind_ok] at h
      cases h2 : requireReadKeys state with
      | error e => rw [h2, except_bind_error] at h; cases h
      | ok readKeys =>
          rw [h2, except_bind_ok] at h
          cases h3 : liftRecord readKeys.update with
          | error e => rw [h3, except_bind_error] at h; cases h
          | ok updatedReadKeys =>
              rw [h3, except_bind_ok] at h
              cases hreq : update.request with
              | updateNotRequested =>
                  simp only [hreq, except_pure, Except.ok.injEq,
                    Prod.mk.injEq] at h
                  rw [← h.1]
              | updateRequested =>
                  simp only [hreq] at h
                  split at h
                  · cases h
                    rfl
                  · rw [sendKeyUpdate_buffered h]

/-- Keep a NewSessionTicket (RFC 9846 §4.6.1): its PSK is the resumption master
secret expanded under "resumption" with the ticket's nonce. A ticket that does
not parse is dropped, which only means no resumption with it. -/
def acceptTicket (state : State) (message : Handshake.Message) : State :=
  match state.resumptionMasterSecret?, Handshake.parseNewSessionTicket message with
  | some resumptionMaster, .ok ticket =>
    let maxEarlyData := match ticket.extensions.find?
        (·.extensionType == Handshake.earlyDataExtension) with
      | some extension =>
        UInt32.ofNat (extension.data.foldl (fun acc b => acc * 256 + b.toNat) 0)
      | none => 0
    { state with tickets := state.tickets.push {
        identity := ticket.ticket
        psk := TLS13.KeySchedule.ticketPsk resumptionMaster ticket.ticketNonce
        ageAdd := ticket.ticketAgeAdd
        lifetime := ticket.ticketLifetime
        maxEarlyData } }
  | _, _ => state

theorem acceptTicket_buffered (state : State) (message : Handshake.Message) :
    (acceptTicket state message).handshakeBuffered = state.handshakeBuffered := by
  unfold acceptTicket; split <;> rfl

/-- Keeping a ticket changes nothing but the ticket list, as an equation. -/
theorem acceptTicket_eq' (state : State) (message : Handshake.Message) :
    acceptTicket state message =
      { state with tickets := (acceptTicket state message).tickets } := by
  unfold acceptTicket; split <;> rfl

/-- Keeping a ticket changes nothing but the ticket list. -/
theorem acceptTicket_eq (state : State) (message : Handshake.Message) :
    ∃ tickets, acceptTicket state message = { state with tickets } := by
  unfold acceptTicket
  split
  · exact ⟨_, rfl⟩
  · exact ⟨state.tickets, rfl⟩

/-- Consume every complete handshake message the buffer holds, in phase order:
EncryptedExtensions, Certificate, CertificateVerify, then the server Finished
that establishes the connection. Public (but not `@[expose]`d) so
`Tls.Client.Laws` can state its key-schedule law as a public theorem. -/
def processHandshakeBuffer (state : State) :
    Except Error (State × ByteArray) :=
  match htake : takeHandshake? state.handshakeBuffered with
  | .error e => .error e
  | .ok none => .ok (state, ByteArray.empty)
  | .ok (some (message, rest)) =>
    have hrest : rest.size < state.handshakeBuffered.size :=
      takeHandshake?_size htake
    let state' := { state with handshakeBuffered := rest }
    match state'.phase with
    | .waitingServerHello =>
        .error (.unexpectedHandshake state'.phase message.msgType)
    | .waitingEncryptedExtensions => do
        unless message.msgType == Handshake.encryptedExtensionsType do
          throw (.unexpectedHandshake state'.phase message.msgType)
        let encryptedExtensions ← liftHandshake (Handshake.parseEncryptedExtensions message)
        let alpnSelected ← liftHandshake (Handshake.selectedAlpnProtocol encryptedExtensions)
        if let some protocol := alpnSelected then
          unless state'.offeredAlpnProtocols.contains protocol do
            throw (.illegalParameter
              s!"server selected ALPN protocol {protocol} that the client did not offer")
        processHandshakeBuffer (appendTranscript
          { state' with
            -- A resumed handshake has no Certificate or CertificateVerify.
            phase := if state'.resumed then .waitingServerFinished else .waitingCertificate
            alpnSelected } message)
    | .waitingCertificate => do
        if message.msgType == Handshake.certificateRequestType then
          if state'.certificateRequested then
            throw (.unexpectedHandshake state'.phase message.msgType)
          let request ← liftHandshake (Handshake.parseCertificateRequest message)
          processHandshakeBuffer (appendTranscript { state' with
            phase := .waitingCertificate
            certificateRequested := true
            clientSignaturePermitted := request.signatureAlgorithms.contains Handshake.ed25519
          } message)
        else
          unless message.msgType == Handshake.certificateType do
            throw (.unexpectedHandshake state'.phase message.msgType)
          let certificate ← liftHandshake (Handshake.parseCertificate message)
          let parsedCertificates ← certificate.entries.mapM fun entry =>
            decodeCertificate entry.der
          let parsedLeaf := parsedCertificates[0]!
          processHandshakeBuffer (appendTranscript {
            state' with
            phase := .waitingCertificateVerify
            leafCertificate? := some certificate.leafDer
            peerCertificates := parsedCertificates
            leafPublicKey? := some parsedLeaf.tbsCertificate.subjectPublicKeyInfo
          } message)
    | .waitingCertificateVerify => do
        unless message.msgType == Handshake.certificateVerifyType do
          throw (.unexpectedHandshake state'.phase message.msgType)
        let certificateVerify ←
          liftHandshake (Handshake.parseCertificateVerify message)
        let some scheme := certificateVerifyScheme? certificateVerify.algorithm
          | throw (.certificateVerifySchemeMismatch certificateVerify.algorithm)
        let publicKey ← requireLeafPublicKey state'
        unless TLS13.X509.Signature.certificateVerifySchemeCompatible
            scheme publicKey do
          throw (.certificateVerifySchemeMismatch certificateVerify.algorithm)
        let transcriptHash := HaclStar.sha256 state'.transcript
        unless TLS13.X509.Signature.verifyServerCertificateVerify
            scheme publicKey transcriptHash certificateVerify.signature do
          throw .certificateVerifyFailed
        processHandshakeBuffer (appendTranscript {
          state' with
          phase := .waitingServerFinished
          leafPublicKey? := none
        } message)
    | .waitingServerFinished => do
        unless message.msgType == Handshake.finishedType do
          throw (.unexpectedHandshake state'.phase message.msgType)
        unless rest.isEmpty do
          throw .trailingHandshakeAfterFinished
        completeServerHandshake state' message
    | .connected =>
        if message.msgType == Handshake.newSessionTicketType then
          processHandshakeBuffer (acceptTicket state' message)
        else if message.msgType == Handshake.keyUpdateType then do
          unless rest.isEmpty do
            -- A KeyUpdate changes the record-protection epoch, so it must end
            -- the protected record in which it appears (RFC 9846 §5.1).
            throw .interleavedHandshake
          match hacc : acceptKeyUpdate state' message with
          | .error e => .error e
          | .ok (stateK, wireBytes) =>
            have hbuf : stateK.handshakeBuffered.size <
                state.handshakeBuffered.size := by
              rw [acceptKeyUpdate_buffered hacc]
              exact hrest
            match processHandshakeBuffer stateK with
            | .error e => .error e
            | .ok (stateF, moreWireBytes) =>
                .ok (stateF, wireBytes ++ moreWireBytes)
        else
          .error (.unexpectedHandshake state'.phase message.msgType)
  termination_by state.handshakeBuffered.size
  decreasing_by
    all_goals first
      | exact hbuf
      | exact hrest
      | (simp only [appendTranscript_buffered]
         exact hrest)
      | (rw [acceptTicket_buffered]
         exact hrest)

private def validCompatibilityChangeCipherSpec (fragment : ByteArray) : Bool :=
  fragment.size == 1 && fragment.get! 0 == 1

private def emitCloseNotify (state : State) : Except Error (State × ByteArray) := do
  if state.localClosed then
    pure (state, ByteArray.empty)
  else
    let writeKeys ← requireWriteKeys state
    let alert := (ByteArray.empty.push 1).push 0
    let (writeKeys, wireBytes) ← liftRecord (Record.«seal» writeKeys .alert alert)
    pure ({ state with writeKeys? := some writeKeys, localClosed := true }, wireBytes)

private def processAlert (state : State) (fragment : ByteArray) (duringHandshake : Bool) :
    Except Error (State × ByteArray) := do
  unless fragment.size == 2 do
    throw (.invalidAlertLength fragment.size)
  let level := fragment.get! 0
  let description := fragment.get! 1
  if description == 0 then
    if duringHandshake then
      throw .peerClosedDuringHandshake
    else
      -- close_notify closes only the peer's write direction; it does not
      -- require an immediate reciprocal close in TLS 1.3.
      pure ({ state with peerClosed := true }, ByteArray.empty)
  else if description == 90 then
    -- user_canceled is informational and must be followed by close_notify.
    pure (state, ByteArray.empty)
  else
    throw (.peerAlert level description)

private def processProtectedRecord (state : State) (record : Record.RawRecord) :
    Except Error (State × ByteArray × ByteArray) := do
  let readKeys ← requireReadKeys state
  let (readKeys, plaintext) ← liftRecord (Record.«open» readKeys record)
  let state := { state with readKeys? := some readKeys }
  if state.phase == .connected then
    if state.peerClosed then
      -- RFC 9846 §6.1: data received after close_notify is ignored.
      pure (state, ByteArray.empty, ByteArray.empty)
    else
      match plaintext.contentType with
      | .applicationData =>
          unless state.handshakeBuffered.isEmpty do
            throw .interleavedHandshake
          pure (state, plaintext.fragment, ByteArray.empty)
      | .handshake =>
          if plaintext.fragment.isEmpty then
            throw (.unexpectedRecord state.phase .handshake)
          let state := {
            state with handshakeBuffered := state.handshakeBuffered ++ plaintext.fragment
          }
          let (state, wireBytes) ← processHandshakeBuffer state
          pure (state, ByteArray.empty, wireBytes)
      | .alert =>
          unless state.handshakeBuffered.isEmpty do
            throw .interleavedHandshake
          let (state, wireBytes) ← processAlert state plaintext.fragment false
          pure (state, ByteArray.empty, wireBytes)
      | .changeCipherSpec =>
          throw (.unexpectedRecord state.phase plaintext.contentType)
  else
    match plaintext.contentType with
    | .handshake =>
        if plaintext.fragment.isEmpty then
          throw (.unexpectedRecord state.phase .handshake)
        let state := {
          state with handshakeBuffered := state.handshakeBuffered ++ plaintext.fragment
        }
        let (state, wireBytes) ← processHandshakeBuffer state
        pure (state, ByteArray.empty, wireBytes)
    | .alert =>
        unless state.handshakeBuffered.isEmpty do
          throw .interleavedHandshake
        let (state, wireBytes) ← processAlert state plaintext.fragment true
        pure (state, ByteArray.empty, wireBytes)
    | contentType =>
        throw (.unexpectedRecord state.phase contentType)

private def processRecord (state : State) (record : Record.RawRecord) :
    Except Error (State × ByteArray × ByteArray) := do
  match state.phase with
  | .waitingServerHello =>
      match record.contentType with
      | .handshake =>
          let (state, wireBytes) ← feedPlaintextHandshake state record.fragment
          pure (state, ByteArray.empty, wireBytes)
      | .changeCipherSpec =>
          unless validCompatibilityChangeCipherSpec record.fragment do
            throw .invalidCompatibilityChangeCipherSpec
          pure (state, ByteArray.empty, ByteArray.empty)
      | .alert =>
          unless state.handshakeBuffered.isEmpty do
            throw .interleavedHandshake
          let (state, wireBytes) ← processAlert state record.fragment true
          pure (state, ByteArray.empty, wireBytes)
      | contentType =>
          throw (.unexpectedRecord state.phase contentType)
  | .waitingEncryptedExtensions
  | .waitingCertificate
  | .waitingCertificateVerify
  | .waitingServerFinished =>
      match record.contentType with
      | .changeCipherSpec =>
          unless validCompatibilityChangeCipherSpec record.fragment do
            throw .invalidCompatibilityChangeCipherSpec
          pure (state, ByteArray.empty, ByteArray.empty)
      | .applicationData => processProtectedRecord state record
      | contentType => throw (.unexpectedRecord state.phase contentType)
  | .connected =>
      match record.contentType with
      | .applicationData => processProtectedRecord state record
      | contentType => throw (.unexpectedRecord state.phase contentType)

/-- Drive `processRecord` over framed records in wire order, accumulating the
decrypted plaintext and the outbound bytes. Written as explicit list recursion
rather than a `for` loop so the engine laws can induct over a whole feed (a
`for` elaborates to `forIn` join points that `split`/`cases` cannot enter). -/
private def processRecords (state : State) (records : List Record.RawRecord)
    (plaintext wireBytes : ByteArray) : Except Failure Output :=
  match records with
  | [] => .ok { state, wireBytes, plaintext }
  | record :: rest =>
    if state.peerClosed then
      .ok { state, wireBytes, plaintext }
    else
      match processRecord state record with
      | .error error => .error { state, error }
      | .ok (next, cleartext, outbound) =>
          processRecords next rest (plaintext ++ cleartext) (wireBytes ++ outbound)

/-- Incrementally consume arbitrary transport bytes, retaining the latest
successfully advanced state on failure for fatal-alert emission. -/
def feedWithFailure (initial : State) (chunk : ByteArray) :
    Except Failure Output :=
  if initial.peerClosed then
    .ok { state := initial }
  else
    match liftRecord (initial.decoder.feed chunk) with
    | .error error => .error { state := initial, error }
    | .ok (decoder, records) =>
        processRecords { initial with decoder } records.toList ByteArray.empty
          ByteArray.empty

/--
Incrementally consume arbitrary transport bytes. The returned plaintext is
the concatenation of application-data records in wire order; `wireBytes`
contains any generated client Finished or reciprocal KeyUpdate. Receiving
`close_notify` only closes the peer's write direction; call `closeNotify`
explicitly when the local write direction should close. Use `feedWithFailure`
when the caller can emit protocol-fatal alerts.
-/
def feed (state : State) (chunk : ByteArray) : Except Error Output :=
  match feedWithFailure state chunk with
  | .ok output => pure output
  | .error failure => throw failure.error

private def concatByteArrays (parts : Array ByteArray) : ByteArray := Id.run do
  let total := parts.foldl (fun size part => size + part.size) 0
  let mut out := ByteArray.mk (Array.replicate total 0)
  let mut offset := 0
  for part in parts do
    out := part.copySlice 0 out offset part.size
    offset := offset + part.size
  return out

private def sealChunks (keys : Record.TrafficKeys) (plaintext : ByteArray)
    (offset : Nat) (records : Array ByteArray) :
    Except Error (Record.TrafficKeys × Array ByteArray) :=
  if plaintext.size ≤ offset then
    .ok (keys, records)
  else
    let stop := min plaintext.size (offset + Record.maxPlaintextLength)
    let chunk := plaintext.extract offset stop
    match liftRecord (Record.«seal» keys .applicationData chunk) with
    | .error e => .error e
    | .ok (keys, wire) => sealChunks keys plaintext stop (records.push wire)
  termination_by plaintext.size - offset
  decreasing_by
    have : 0 < Record.maxPlaintextLength := by decide
    omega

/-- Protect application bytes, splitting them at TLS's 2^14-byte limit. -/
def sealApplication (state : State) (plaintext : ByteArray) : Except Error Output := do
  unless state.phase == .connected do
    throw (.notConnected state.phase)
  if state.localClosed then
    throw .connectionClosed
  if plaintext.isEmpty then
    pure { state }
  else
    let writeKeys ← requireWriteKeys state
    let (writeKeys, records) ← sealChunks writeKeys plaintext 0 #[]
    let wireBytes := concatByteArrays records
    pure { state := { state with writeKeys? := some writeKeys }, wireBytes }

/--
Send `close_notify` under the current application keys.  Repeated calls are a
no-op and return the same state with empty `wireBytes`.
-/
def closeNotify (state : State) : Except Error Output := do
  unless state.phase == .connected do
    throw (.notConnected state.phase)
  let (state, wireBytes) ← emitCloseNotify state
  pure { state, wireBytes }

/-! ## Runs

A connection is driven by a sequence of caller operations. `run` folds them
purely, which gives the state-machine laws in `Tls.Client.Laws` a single object
to quantify over — in particular the nonce non-reuse theorem, which is about
everything one run of the engine protects. -/

/-- One caller-driven step of a client connection. -/
inductive Op where
  /-- Transport bytes arrived. -/
  | feed (chunk : ByteArray)
  /-- Application bytes to protect and send. -/
  | send (plaintext : ByteArray)
  /-- Send `close_notify`. -/
  | close
  /-- Seal a fatal alert; the caller discards the connection afterwards. -/
  | fatalAlert (description : UInt8)
  /-- Send a KeyUpdate, asking the peer for one too when `requestPeer`. -/
  | keyUpdate (requestPeer : Bool)
  deriving Inhabited

def step (state : State) (op : Op) : Except Error Output :=
  match op with
  | .feed chunk => feed state chunk
  | .send plaintext => sealApplication state plaintext
  | .close => closeNotify state
  | .fatalAlert description => sealFatalAlert state description
  | .keyUpdate requestPeer => updateKeys state requestPeer

/-- Drive a sequence of operations from `state`, concatenating produced wire
bytes and plaintext in order. -/
def run (state : State) (ops : List Op) : Except Error Output :=
  match ops with
  | [] => .ok { state }
  | op :: rest =>
    match step state op with
    | .error e => .error e
    | .ok out =>
      match run out.state rest with
      | .error e => .error e
      | .ok final =>
        .ok { final with
          wireBytes := out.wireBytes ++ final.wireBytes
          plaintext := out.plaintext ++ final.plaintext }

end Client
end Tls
