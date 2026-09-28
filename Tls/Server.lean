module

public import HaclStar.Aead
public import HaclStar.Curve25519
public import HaclStar.Hmac
public import HaclStar.P256
public import HaclStar.Sha256
public import HaclStar.Signature
public import Tls.Handshake
public import Tls.Identity
public import Tls.Record
public import TLS13.KeySchedule
public import TLS13.X509
public import TLS13.Rfc6979

public section

namespace Tls
namespace Server

/-!
A pure, sans-I/O TLS 1.3 *server* handshake and record machine — the mirror of
`Tls.Client`. It performs no I/O and obtains no entropy itself: the caller
supplies the ServerHello random and ephemeral private scalar(s), the DER
certificate chain, and the Ed25519 signing key in `Config`, then feeds transport
bytes to `feed` and writes the returned `wireBytes`.

The single supported cipher suite matches the client:
TLS_CHACHA20_POLY1305_SHA256. The server negotiates that suite from the
client's offered set and chooses X25519 (or P-256 when configured) from
supported_groups. When the preferred mutual group has no first-flight share,
the server performs one HelloRetryRequest with the RFC 8446 synthetic
message_hash transcript. Authentication is Ed25519; PSK and client
authentication are unsupported. ALPN is negotiated and the selected
protocol is surfaced in `State.alpnSelected` so the caller can route h2 (gRPC)
versus http/1.1 (REST).
-/

/-- Server certificate, key, and policy. Under RFC 9846 §4.3.8, each
ephemeral private scalar must be generated independently and must never be
reused across connections. This pure API cannot obtain entropy, so freshness is
a caller obligation. `signingKey` is the 32-byte Ed25519 private scalar for the
leaf. -/
structure ClientAuthPolicy where
  trustStore : TLS13.X509.Chain.TrustStore
  /-- Current Unix time captured for this handshake, not process startup. -/
  now : Int
  required : Bool := true
  requireExplicitPurpose : Bool := true
  maximumCertificateBytes : Nat := 1048576
  maximumCertificates : Nat := 10
  deriving Inhabited

/-- An outstanding post-handshake CertificateRequest (RFC 9846 §4.6.2) and the
client's answer so far, kept apart from the handshake's own client-auth fields
so that a connected server never looks mid-handshake. -/
structure PostAuth where
  policy : ClientAuthPolicy
  context : ByteArray
  /-- The handshake transcript, the CertificateRequest, and what has arrived. -/
  transcript : ByteArray
  expectedFinished? : Option ByteArray := none
  received : Bool := false
  verified : Bool := false
  pending : Array TLS13.X509.Certificate := #[]
  peer : Array TLS13.X509.Certificate := #[]

/-- The algorithm the server's CertificateVerify is signed with. -/
inductive SigningAlgorithm where
  /-- RFC 8032 Ed25519 (`ed25519`, 0x0807). -/
  | ed25519
  /-- ECDSA P-256 with SHA-256 (`ecdsa_secp256r1_sha256`, 0x0403), which
  RFC 9846 §9.1 makes mandatory to support; nonces per RFC 6979. -/
  | ecdsaP256Sha256
  deriving Repr, BEq, DecidableEq, Inhabited

/-- The TLS SignatureScheme code point. -/
def SigningAlgorithm.scheme : SigningAlgorithm → UInt16
  | .ed25519 => Handshake.ed25519
  | .ecdsaP256Sha256 => Handshake.ecdsaSecp256r1Sha256

/-- The algorithm's name in messages. -/
def SigningAlgorithm.name : SigningAlgorithm → String
  | .ed25519 => "Ed25519"
  | .ecdsaP256Sha256 => "ECDSA P-256"

/-- The X.509 view of the scheme, for checking the leaf's public key. -/
def SigningAlgorithm.certificateVerifyScheme :
    SigningAlgorithm → TLS13.X509.Signature.CertificateVerifyScheme
  | .ed25519 => .ed25519
  | .ecdsaP256Sha256 => .ecdsaSecp256r1Sha256

structure Config where
  serverRandom : ByteArray
  x25519Private : ByteArray
  /-- Optional P-256 ephemeral, used only when a client offers no X25519 share. -/
  p256Private : Option ByteArray := none
  /-- DER certificates, leaf first. -/
  certificateChain : Array ByteArray
  /-- The 32-byte private scalar matching the leaf certificate's public key,
  for `signingAlgorithm`. The leaf must carry a matching SPKI and, when
  KeyUsage is present, permit `digitalSignature`; `checkConfig` verifies those
  public certificate fields, and for P-256 that the key is the leaf's. -/
  signingKey : ByteArray
  signingAlgorithm : SigningAlgorithm := .ed25519
  /-- ALPN protocols the server supports, in server preference order. The first
  one the client also offers is selected. Empty disables ALPN. -/
  alpnProtocols : List String := []
  clientAuth : Option ClientAuthPolicy := none
  /-- A 32-byte key that seals this server's session tickets. With it,
  `issueTicket` sends NewSessionTickets once connected, and a ClientHello that
  offers such a ticket resumes (RFC 9846 §2.2, psk_dhe_ke only). Rotating it
  retires every ticket sealed under the old one. -/
  ticketKey : Option ByteArray := none
  /-- Ticket lifetime in seconds, at most 604800 (seven days). -/
  ticketLifetime : UInt32 := 7200
  /-- The current time, in milliseconds since the Unix epoch, for stamping new
  tickets and checking an offered ticket's lifetime. The engine reads no clock. -/
  nowMs : Nat := 0
  /-- Validation policy for client certificates requested after the handshake
  (RFC 9846 §4.6.2), with `requestClientCertificate`, when the client offered
  post_handshake_auth. -/
  postHandshakeAuth : Option ClientAuthPolicy := none
  deriving Inhabited

inductive Phase where
  | waitingClientHello
  | waitingSecondClientHello
  | waitingClientFinished
  | connected
  deriving Repr, BEq, DecidableEq, Inhabited

namespace Phase

def render : Phase → String
  | .waitingClientHello => "ClientHello"
  | .waitingSecondClientHello => "second ClientHello after HelloRetryRequest"
  | .waitingClientFinished => "client Finished"
  | .connected => "post-handshake message"

end Phase

inductive Error where
  | invalidConfig (message : String)
  | handshakeCodec (message : String)
  | recordLayer (error : Record.Error)
  | missingRequiredExtension (extensionType : UInt16)
  | noSupportedCipherSuite
  | noSupportedGroup
  | noSupportedSignatureScheme
  | invalidClientKeyShare (group : Handshake.NamedGroup) (message : String)
  | invalidRetryClientHello (message : String)
  | keyExchangeFailed
  | clientDidNotOfferTls13
  | signingFailed
  | clientFinishedMismatch
  | badClientCertificate
  | clientCertificateRequired
  | clientCertificateVerifyFailed
  | unexpectedRecord (phase : Phase) (contentType : Record.ContentType)
  | unexpectedHandshake (phase : Phase) (actual : UInt8)
  | invalidCompatibilityChangeCipherSpec
  | interleavedHandshake
  | invalidAlertLength (actual : Nat)
  | invalidAlertLevel (actual : UInt8)
  | illegalParameter (message : String)
  | peerAlert (level description : UInt8)
  | peerClosedDuringHandshake
  | notConnected (phase : Phase)
  | connectionClosed
  | keyUpdateLimit
  | pskBinderMismatch
  | invalidExporterRequest (message : String)
  | internalState (message : String)
  deriving Repr, Inhabited

namespace Error

def render : Error → String
  | .badClientCertificate => "TLS client certificate validation failed"
  | .clientCertificateRequired => "TLS client certificate is required"
  | .clientCertificateVerifyFailed => "TLS client CertificateVerify failed"
  | .invalidConfig message => s!"invalid TLS server config: {message}"
  | .handshakeCodec message => s!"TLS handshake codec: {message}"
  | .recordLayer error => s!"TLS record layer: {error}"
  | .missingRequiredExtension extensionType =>
      s!"TLS 1.3 ClientHello is missing required extension {extensionType}"
  | .noSupportedCipherSuite =>
      "client offered no supported cipher suite (need TLS_CHACHA20_POLY1305_SHA256)"
  | .noSupportedGroup =>
      "client offered no mutually supported group (need X25519 or configured P-256)"
  | .noSupportedSignatureScheme =>
      "client offered no signature scheme usable with the server's key"
  | .invalidClientKeyShare group message =>
      s!"invalid client {repr group} key share: {message}"
  | .invalidRetryClientHello message =>
      s!"invalid second ClientHello after HelloRetryRequest: {message}"
  | .keyExchangeFailed => "TLS key exchange rejected the client public key"
  | .clientDidNotOfferTls13 => "client did not offer TLS 1.3 in supported_versions"
  | .signingFailed => "server CertificateVerify signing failed"
  | .clientFinishedMismatch => "client Finished verification failed"
  | .unexpectedRecord phase contentType =>
      s!"unexpected TLS {repr contentType} record while waiting for {phase.render}"
  | .unexpectedHandshake phase actual =>
      s!"unexpected TLS handshake message {actual} while waiting for {phase.render}"
  | .invalidCompatibilityChangeCipherSpec => "invalid TLS 1.3 compatibility ChangeCipherSpec"
  | .interleavedHandshake => "TLS handshake fragments were interleaved with another content type"
  | .invalidAlertLength actual => s!"TLS alert payload must be two bytes, got {actual}"
  | .invalidAlertLevel actual => s!"invalid TLS alert level {actual}"
  | .illegalParameter message => s!"illegal TLS parameter: {message}"
  | .peerAlert level description => s!"TLS peer alert level {level}, description {description}"
  | .peerClosedDuringHandshake => "TLS peer sent close_notify during the handshake"
  | .notConnected phase => s!"TLS connection not ready for application data (waiting for {phase.render})"
  | .connectionClosed => "TLS connection is closed"
  | .keyUpdateLimit => "TLS KeyUpdate limit of 2^48-1 sending epochs reached"
  | .pskBinderMismatch => "TLS PSK binder verification failed"
  | .invalidExporterRequest message => s!"TLS exporter: {message}"
  | .internalState message => s!"invalid internal TLS server state: {message}"

/-- Fatal alert to seal (when write keys exist) before discarding the connection. -/
def fatalAlertDescription? : Error → Option UInt8
  | .badClientCertificate => some 42
  | .clientCertificateRequired => some 116
  | .clientCertificateVerifyFailed => some 51
  | .handshakeCodec _ => some 50            -- decode_error
  | .unexpectedHandshake _ _ => some 10     -- unexpected_message
  | .unexpectedRecord _ _ => some 10
  | .interleavedHandshake => some 10
  | .invalidAlertLength 0 => some 10
  | .invalidAlertLength _ => some 50
  | .clientFinishedMismatch => some 51      -- decrypt_error
  | .pskBinderMismatch => some 51           -- decrypt_error
  | .missingRequiredExtension _ => some 109 -- missing_extension
  | .noSupportedCipherSuite => some 40      -- handshake_failure
  | .noSupportedGroup => some 40            -- handshake_failure
  | .noSupportedSignatureScheme => some 40  -- handshake_failure
  | .invalidClientKeyShare _ _ => some 47   -- illegal_parameter
  | .invalidRetryClientHello _ => some 47   -- illegal_parameter
  | .keyExchangeFailed => some 47        -- illegal_parameter
  | .illegalParameter _ => some 47       -- illegal_parameter
  | .clientDidNotOfferTls13 => some 70      -- protocol_version
  | _ => none

end Error

instance : ToString Error := ⟨Error.render⟩

/-- Pure server connection state. No `Repr` instance: secrets never print. -/
structure State where
  phase : Phase
  decoder : Record.Decoder := {}
  handshakeBuffered : ByteArray := ByteArray.empty
  transcript : ByteArray := ByteArray.empty
  -- Config carried through the handshake, cleared once connected.
  serverRandom : ByteArray
  x25519Private : ByteArray
  p256Private : Option ByteArray := none
  certificateChain : Array ByteArray := #[]
  signingKey : ByteArray
  signingAlgorithm : SigningAlgorithm := .ed25519
  alpnProtocols : List String := []
  clientAuth : Option ClientAuthPolicy := none
  clientCertificateReceived : Bool := false
  clientCertificateVerified : Bool := false
  pendingClientCertificates : Array TLS13.X509.Certificate := #[]
  /-- Populated only after chain validation and client proof of possession. -/
  peerCertificates : Array TLS13.X509.Certificate := #[]
  clientHandshakeSecret? : Option ByteArray := none
  -- Negotiated results, surfaced to the caller.
  alpnSelected : Option String := none
  peerServerName : Option String := none
  cipherSuiteSelected : Option UInt16 := none
  groupSelected : Option Handshake.NamedGroup := none
  -- HelloRetryRequest state. `transcript` is message_hash(CH1) || HRR while
  -- waiting for CH2, and is cleared once the final server flight is built.
  retryGroup? : Option Handshake.NamedGroup := none
  /-- The first ClientHello, exactly as parsed. The second one is compared
  against it field by field (`checkRetryClientHello`); by
  `Handshake.parseClientHello_canonical` those fields *are* the message bytes,
  which is what `checkRetryClientHello_body_eq` makes precise. -/
  retryHello? : Option Handshake.ClientHello := none
  compatibilityCcsSent : Bool := false
  -- Traffic keys.
  readKeys? : Option Record.TrafficKeys := none
  writeKeys? : Option Record.TrafficKeys := none
  clientApplicationKeys? : Option Record.TrafficKeys := none
  expectedClientFinished? : Option ByteArray := none
  /-- The master secret, kept from the server flight until the client Finished
  fixes the transcript that `resumption_master_secret` binds. -/
  masterSecret? : Option ByteArray := none
  /-- RFC 9846 §7.1 `resumption_master_secret`, once connected. -/
  resumptionMasterSecret? : Option ByteArray := none
  ticketKey : Option ByteArray := none
  ticketLifetime : UInt32 := 7200
  nowMs : Nat := 0
  /-- NewSessionTickets sent so far; the next one's ticket_nonce. -/
  ticketsIssued : Nat := 0
  /-- This connection resumed a session with a PSK. -/
  resumed : Bool := false
  postHandshakeAuth : Option ClientAuthPolicy := none
  /-- The ClientHello carried post_handshake_auth. -/
  clientOffersPostHandshakeAuth : Bool := false
  /-- ClientHello…client Finished, kept once connected when post-handshake
  authentication is possible: each such authentication binds it. -/
  handshakeTranscript : ByteArray := ByteArray.empty
  /-- The outstanding post-handshake CertificateRequest, if any. -/
  postAuth? : Option PostAuth := none
  /-- The certificate_request_context client Certificates must carry: empty in
  the handshake, the request's own context after it. -/
  certificateRequestContext : ByteArray := ByteArray.empty
  /-- Post-handshake client authentications completed. -/
  postHandshakeAuthentications : Nat := 0
  /-- RFC 9846 §7.1 `exporter_master_secret`, derived with the server flight and
  served by `exportKeyingMaterial` once the client Finished verifies. -/
  exporterMasterSecret? : Option ByteArray := none
  /-- Number of reciprocal KeyUpdate messages emitted in the application
  sending epoch chain. RFC 9846 §4.7.3 caps this at `2^48 - 1`. -/
  sendingKeyUpdates : Nat := 0
  localClosed : Bool := false
  peerClosed : Bool := false
  deriving Inhabited

namespace State

def connected (state : State) : Bool :=
  state.phase == .connected

def closed (state : State) : Bool :=
  state.localClosed && state.peerClosed

end State

/-- RFC 9846 §4.7.3's maximum number of KeyUpdate messages that one side
may send on a connection. -/
def maxSendingKeyUpdates : Nat := (2 ^ 48) - 1

/-- Bytes and state produced by every engine operation. -/
structure Output where
  state : State
  wireBytes : ByteArray := ByteArray.empty
  plaintext : ByteArray := ByteArray.empty
  deriving Inhabited

structure Failure where
  state : State
  error : Error

/-! ## Shared helpers (mirror of the client engine). -/

private def liftHandshake {α : Type} (result : Except String α) : Except Error α :=
  result.mapError Error.handshakeCodec

private def liftRecord {α : Type} (result : Except Record.Error α) : Except Error α :=
  result.mapError Error.recordLayer

/-- Protect a server handshake flight, splitting it at TLS's 2^14-byte record
limit and returning the advanced traffic state alongside the wire bytes.
Explicit well-founded recursion (not a `while` loop, whose `Loop.forIn` is
`partial` and therefore opaque to proofs) so the nonce laws can account for
every record it protects. -/
private def sealHandshakeFlight (keys : Record.TrafficKeys) (flight : ByteArray)
    (offset : Nat) (wireBytes : ByteArray) :
    Except Error (Record.TrafficKeys × ByteArray) :=
  if flight.size ≤ offset then
    .ok (keys, wireBytes)
  else
    let stop := min flight.size (offset + Record.maxPlaintextLength)
    match liftRecord (Record.«seal» keys .handshake (flight.extract offset stop)) with
    | .error e => .error e
    | .ok (keys, record) => sealHandshakeFlight keys flight stop (wireBytes ++ record)
  termination_by flight.size - offset
  decreasing_by
    have : 0 < Record.maxPlaintextLength := by decide
    omega

private def requireReadKeys (state : State) : Except Error Record.TrafficKeys :=
  match state.readKeys? with
  | some keys => pure keys
  | none => throw (.internalState "missing read traffic keys")

private def requireWriteKeys (state : State) : Except Error Record.TrafficKeys :=
  match state.writeKeys? with
  | some keys => pure keys
  | none => throw (.internalState "missing write traffic keys")

private def emptyTranscriptHash : ByteArray :=
  HaclStar.sha256 ByteArray.empty

private theorem liftHandshake_ok {α : Type} {result : Except String α}
    {value : α} (h : liftHandshake result = .ok value) : result = .ok value := by
  unfold liftHandshake at h
  cases result with
  | error e => simp [Except.mapError] at h
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

private def validCompatibilityChangeCipherSpec (fragment : ByteArray) : Bool :=
  fragment.size == 1 && fragment.get! 0 == 1

/-! ## Handshake construction. -/

/-- Build the initial state; the server sends nothing until it sees a ClientHello. -/
def start (config : Config) : State :=
  {
    phase := .waitingClientHello
    serverRandom := config.serverRandom
    x25519Private := config.x25519Private
    p256Private := config.p256Private
    certificateChain := config.certificateChain
    signingKey := config.signingKey
    signingAlgorithm := config.signingAlgorithm
    alpnProtocols := config.alpnProtocols
    clientAuth := config.clientAuth
    ticketKey := config.ticketKey
    ticketLifetime := config.ticketLifetime
    nowMs := config.nowMs
    postHandshakeAuth := config.postHandshakeAuth
  }

private def clientShare? (hello : Handshake.ClientHello) (group : Handshake.NamedGroup) :
    Option ByteArray :=
  (hello.keyShares.find? (fun share => share.group == group)).map (·.keyExchange)

/-- Select the server's preferred mutually supported group. Group negotiation
is based on supported_groups, not merely on the first-flight key_share list:
the latter distinction is what makes HelloRetryRequest possible. -/
private def selectGroup (state : State) (hello : Handshake.ClientHello) :
    Except Error Handshake.NamedGroup := do
  if hello.supportedGroups.contains .x25519 then
    pure .x25519
  else
    match state.p256Private with
    | some _ =>
        if hello.supportedGroups.contains .secp256r1 then
          pure .secp256r1
        else
          throw .noSupportedGroup
    | none => throw .noSupportedGroup

/-- Compute the ECDHE result for an already negotiated group. Returns
`(serverPublicValue, sharedSecret)`. -/
private def keyExchange (state : State) (hello : Handshake.ClientHello)
    (group : Handshake.NamedGroup) : Except Error (ByteArray × ByteArray) := do
  let some clientPublic := clientShare? hello group
    | throw (.invalidClientKeyShare group "missing requested key share")
  match group with
  | .x25519 =>
      unless clientPublic.size == 32 do
        throw (.invalidClientKeyShare group
          s!"X25519 public value must be 32 bytes, got {clientPublic.size}")
      let some shared := HaclStar.X25519.ecdh state.x25519Private clientPublic
        | throw .keyExchangeFailed
      pure (HaclStar.X25519.base state.x25519Private, shared)
  | .secp256r1 =>
      let some p256Private := state.p256Private
        | throw (.internalState "P-256 was selected without a configured ephemeral")
      unless clientPublic.size == 65 && clientPublic.get! 0 == 4 do
        throw (.invalidClientKeyShare group
          "P-256 public value must be a 65-byte uncompressed point")
      let some serverPublic := HaclStar.P256.publicKey p256Private
        | throw (.internalState "server P-256 ephemeral produced no public key")
      let some shared := HaclStar.P256.ecdh p256Private clientPublic
        | throw .keyExchangeFailed
      pure (serverPublic, shared)

private def parseOfferedPsks (hello : Handshake.ClientHello) :
    Except String (Option (Array (ByteArray × Nat))) := do
  let some extension := hello.extensions.find?
      (fun extension =>
        extension.extensionType == Handshake.preSharedKeyExtension)
    | pure none
  let r : Handshake.Reader := { bytes := extension.data }
  let (identitiesBytes, r) ← r.readVector16
  let (bindersBytes, r) ← r.readVector16
  r.requireEnd "ClientHello pre_shared_key"

  let mut identities : Array ByteArray := #[]
  let mut ir : Handshake.Reader := { bytes := identitiesBytes }
  while !ir.atEnd do
    let (identity, ir') ← ir.readVector16
    if identity.isEmpty then
      throw "ClientHello PSK identity must not be empty"
    let (_, ir') ← ir'.readUInt32
    identities := identities.push identity
    ir := ir'
  if identities.isEmpty then
    throw "ClientHello PSK identities must not be empty"

  let mut binderLengths : Array Nat := #[]
  let mut br : Handshake.Reader := { bytes := bindersBytes }
  while !br.atEnd do
    let (binder, br') ← br.readVector8
    if binder.size < 32 then
      throw s!"ClientHello PSK binder is too short ({binder.size} bytes)"
    binderLengths := binderLengths.push binder.size
    br := br'
  unless binderLengths.size == identities.size do
    throw "ClientHello PSK identity and binder counts differ"

  let mut psks : Array (ByteArray × Nat) := #[]
  for i in [0:identities.size] do
    psks := psks.push (identities[i]!, binderLengths[i]!)
  pure (some psks)

private def psksAreOrderedSubset (subset superset : Array (ByteArray × Nat)) :
    Bool := Id.run do
  let mut next := 0
  for psk in subset do
    let mut found := false
    while next < superset.size && !found do
      if superset[next]! == psk then
        found := true
      next := next + 1
    unless found do
      return false
  return true

private def checkCommonOffers (hello : Handshake.ClientHello) (scheme : UInt16) :
    Except Error Unit := do
  unless hello.offersTls13 do
    throw .clientDidNotOfferTls13
  let hasExtension (extensionType : UInt16) : Bool :=
    hello.extensions.any (fun extension =>
      extension.extensionType == extensionType)
  unless hasExtension Handshake.supportedGroupsExtension do
    throw (.missingRequiredExtension Handshake.supportedGroupsExtension)
  unless hasExtension Handshake.keyShareExtension do
    throw (.missingRequiredExtension Handshake.keyShareExtension)
  unless hasExtension Handshake.signatureAlgorithmsExtension do
    throw (.missingRequiredExtension Handshake.signatureAlgorithmsExtension)
  unless hello.cipherSuites.contains Handshake.tlsChaCha20Poly1305Sha256 do
    throw .noSupportedCipherSuite
  unless hello.signatureAlgorithms.contains scheme do
    throw .noSupportedSignatureScheme
  let _ ← liftHandshake (parseOfferedPsks hello)

private def retryStableExtensions (hello : Handshake.ClientHello) :
    Array Handshake.Extension :=
  hello.extensions.filter fun extension =>
    -- RFC 8446 §4.1.2 permits replacing key_share, removing early_data,
    -- updating a PSK binder, and changing padding. This server sends no
    -- cookie, so a cookie is checked separately and cannot appear in CH2.
    extension.extensionType != Handshake.keyShareExtension &&
      extension.extensionType != Handshake.earlyDataExtension &&
      extension.extensionType != Handshake.preSharedKeyExtension &&
      extension.extensionType != Handshake.cookieExtension &&
      extension.extensionType != Handshake.paddingExtension

/-- RFC 8446 §4.1.2: everything a second ClientHello must repeat unchanged after
a HelloRetryRequest, plus the retry-specific requirements on the fields it *is*
allowed to change (early_data must be gone, no unsolicited cookie, the PSK offer
may only lose identities incompatible with the selected hash, and key_share must
carry exactly the requested group).

The comparison is against the first ClientHello *as parsed*. That is exactly as
strong as comparing the two messages byte for byte:
`Handshake.parseClientHello_canonical` proves a parsed ClientHello re-encodes to
the body it came from, and `checkRetryClientHello_body_eq` below turns this
check plus an unchanged extension list into byte equality of the two bodies. -/
def checkRetryClientHello (first second : Handshake.ClientHello)
    (group : Handshake.NamedGroup) : Except Error Unit := do
  unless second.random == first.random do
    throw (.invalidRetryClientHello "random changed")
  unless second.legacySessionId == first.legacySessionId do
    throw (.invalidRetryClientHello "legacy_session_id changed")
  unless second.cipherSuites == first.cipherSuites do
    throw (.invalidRetryClientHello "cipher_suites changed")
  unless second.supportedVersionIds == first.supportedVersionIds do
    throw (.invalidRetryClientHello "supported_versions changed")
  unless second.supportedGroupIds == first.supportedGroupIds do
    throw (.invalidRetryClientHello "supported_groups changed")
  unless second.signatureAlgorithms == first.signatureAlgorithms do
    throw (.invalidRetryClientHello "signature_algorithms changed")
  unless second.serverName == first.serverName do
    throw (.invalidRetryClientHello "server_name changed")
  unless second.alpnProtocols == first.alpnProtocols do
    throw (.invalidRetryClientHello "ALPN offer changed")
  unless retryStableExtensions second == retryStableExtensions first do
    throw (.invalidRetryClientHello "an extension not permitted to change was modified")
  if second.extensions.any
      (fun extension => extension.extensionType == Handshake.earlyDataExtension) then
    throw (.invalidRetryClientHello "early_data was not removed")
  if second.extensions.any
      (fun extension => extension.extensionType == Handshake.cookieExtension) then
    throw (.invalidRetryClientHello "unsolicited cookie extension")
  let currentPsks ← liftHandshake (parseOfferedPsks second)
  let originalPsks ← liftHandshake (parseOfferedPsks first)
  match currentPsks, originalPsks with
  | none, none => pure ()
  | none, some original =>
      if original.any (fun psk => psk.2 == 32) then
        throw (.invalidRetryClientHello
          "pre_shared_key removed despite containing a SHA-256 identity")
  | some _, none =>
      throw (.invalidRetryClientHello "pre_shared_key was added")
  | some current, some original =>
      let required := original.filter (fun psk => psk.2 == 32)
      unless psksAreOrderedSubset current original &&
          psksAreOrderedSubset required current do
        throw (.invalidRetryClientHello
          "pre_shared_key identities were added, reordered, changed, or \
            removed despite matching SHA-256")
  unless second.supportedGroups.contains group do
    throw (.invalidRetryClientHello "requested group was removed from supported_groups")
  unless second.keyShareGroupIds == #[group.toUInt16] do
    throw (.invalidRetryClientHello
      "key_share must contain exactly the single group requested by HelloRetryRequest")
  unless (clientShare? second group).isSome do
    throw (.invalidRetryClientHello "requested key share is still absent")

private def checkConfig (state : State) : Except Error Unit := do
  unless state.serverRandom.size == 32 do
    throw (.invalidConfig s!"ServerHello random must be 32 bytes, got {state.serverRandom.size}")
  if state.serverRandom == Handshake.helloRetryRequestRandom then
    throw (.invalidConfig "ServerHello random equals the reserved HelloRetryRequest value")
  unless state.x25519Private.size == 32 do
    throw (.invalidConfig
      s!"X25519 private scalar must be 32 bytes, got {state.x25519Private.size}")
  if let some privateKey := state.p256Private then
    unless privateKey.size == 32 do
      throw (.invalidConfig s!"P-256 private scalar must be 32 bytes, got {privateKey.size}")
  if state.certificateChain.isEmpty then
    throw (.invalidConfig "certificate chain must not be empty")
  if state.certificateChain.any ByteArray.isEmpty then
    throw (.invalidConfig "certificate chain contains an empty DER entry")
  let leaf ← match TLS13.X509.Certificate.decode state.certificateChain[0]! with
    | .ok certificate => pure certificate
    | .error message =>
        throw (.invalidConfig s!"leaf certificate is not strict DER: {message}")
  unless TLS13.X509.Chain.leafKeyUsagePermitsDigitalSignature leaf do
    throw (.invalidConfig
      "leaf certificate KeyUsage does not permit TLS digital signatures")
  unless TLS13.X509.Chain.permitsPurpose leaf .serverAuth do
    throw (.invalidConfig "leaf certificate purpose does not permit server authentication")
  unless TLS13.X509.Signature.certificateVerifySchemeCompatible
      state.signingAlgorithm.certificateVerifyScheme
      leaf.tbsCertificate.subjectPublicKeyInfo do
    throw (.invalidConfig
      s!"leaf certificate public key is not compatible with {state.signingAlgorithm.name} CertificateVerify")
  unless state.signingKey.size == 32 do
    throw (.invalidConfig
      s!"signing key must be 32 bytes, got {state.signingKey.size}")
  if state.signingAlgorithm == .ecdsaP256Sha256 then
    unless (match leaf.tbsCertificate.subjectPublicKeyInfo.key with
        | .p256 point => HaclStar.P256.publicKey state.signingKey == some point
        | _ => false) do
      throw (.invalidConfig "P-256 signing key does not match the leaf certificate")
  if let some key := state.ticketKey then
    unless key.size == 32 do
      throw (.invalidConfig s!"ticket key must be 32 bytes, got {key.size}")
  if state.ticketLifetime > 604800 then
    throw (.invalidConfig "ticket lifetime exceeds seven days")

/-- The server CertificateVerify signature, or empty if signing failed: a
64-byte Ed25519 signature, or a DER ECDSA-Sig-Value with an RFC 6979 nonce. -/
private def certificateVerifySignature (algorithm : SigningAlgorithm)
    (key content : ByteArray) : ByteArray :=
  match algorithm with
  | .ed25519 =>
    let signature := HaclStar.Signature.ed25519Sign key content
    if signature.size == 64 then signature else ByteArray.empty
  | .ecdsaP256Sha256 => (TLS13.Rfc6979.signP256 key content).getD ByteArray.empty

/-- Choose the first server-preferred ALPN protocol the client also offered. -/
private def selectAlpn (serverProtocols : List String) (clientProtocols : Array String) :
    Option String :=
  serverProtocols.find? (fun protocol => clientProtocols.contains protocol)

private def certificateRequestFlight (state : State) : Except Error ByteArray := do
  if state.clientAuth.isSome then
    pure (← liftHandshake Handshake.encodeCertificateRequest).encoded
  else pure ByteArray.empty

/-- Given a ClientHello with the selected group's key share, derive keys, build
the full server flight (ServerHello, then encrypted EncryptedExtensions/
Certificate/CertificateVerify/Finished), and advance to
`waitingClientFinished`. `transcriptPrefix` is either CH1 or
message_hash(CH1)||HRR||CH2. -/
def completeClientHello (state : State) (hello : Handshake.ClientHello)
    (group : Handshake.NamedGroup)
    (transcriptPrefix : ByteArray) :
    Except Error (State × ByteArray) := do
  let (serverPublic, sharedSecret) ← keyExchange state hello group
  unless sharedSecret.size == TLS13.KeySchedule.hashLen do
    throw (.internalState s!"ECDHE returned a {sharedSecret.size}-byte shared secret")

  -- ServerHello and handshake-traffic secrets.
  let serverHello ← liftHandshake
    (Handshake.encodeServerHello state.serverRandom hello.legacySessionId group serverPublic)
  let earlySecret := TLS13.KeySchedule.earlySecret
  let handshakeSecret :=
    TLS13.KeySchedule.handshakeSecret earlySecret sharedSecret emptyTranscriptHash
  let transcript := transcriptPrefix ++ serverHello.encoded
  let serverHelloHash := HaclStar.sha256 transcript
  let clientHandshakeSecret :=
    TLS13.KeySchedule.deriveSecret handshakeSecret "c hs traffic" serverHelloHash
  let serverHandshakeSecret :=
    TLS13.KeySchedule.deriveSecret handshakeSecret "s hs traffic" serverHelloHash
  let serverWriteKeys ← liftRecord (Record.deriveTrafficKeys serverHandshakeSecret)
  let clientReadKeys ← liftRecord (Record.deriveTrafficKeys clientHandshakeSecret)

  -- EncryptedExtensions (ALPN) and Certificate.
  let alpnSelected := selectAlpn state.alpnProtocols hello.alpnProtocols
  let encryptedExtensions ← liftHandshake (Handshake.encodeEncryptedExtensions alpnSelected)
  let transcript := transcript ++ encryptedExtensions.encoded
  let requestBytes ← certificateRequestFlight state
  let transcript := transcript ++ requestBytes
  let certificate ← liftHandshake (Handshake.encodeCertificate state.certificateChain)
  let transcript := transcript ++ certificate.encoded

  -- CertificateVerify: sign the standard content over the transcript hash.
  let certVerifyContent ←
    match TLS13.X509.Signature.serverCertificateVerifyContent (HaclStar.sha256 transcript) with
    | .ok content => pure content
    | .error message => throw (.internalState message)
  let signature := certificateVerifySignature state.signingAlgorithm state.signingKey
    certVerifyContent
  unless !signature.isEmpty do
    throw .signingFailed
  let certVerify ← liftHandshake
    (Handshake.encodeCertificateVerify state.signingAlgorithm.scheme signature)
  let transcript := transcript ++ certVerify.encoded

  -- Server Finished.
  let serverVerifyData := finishedVerifyData serverHandshakeSecret (HaclStar.sha256 transcript)
  let serverFinished ← liftHandshake (Handshake.encodeFinished serverVerifyData)
  let transcript := transcript ++ serverFinished.encoded
  let finishedHash := HaclStar.sha256 transcript

  -- The client's Finished is over the transcript through the server Finished.
  let expectedClientFinished := finishedVerifyData clientHandshakeSecret finishedHash

  -- Application-traffic keys.
  let masterSecret := TLS13.KeySchedule.masterSecret handshakeSecret emptyTranscriptHash
  let serverApplicationSecret :=
    TLS13.KeySchedule.deriveSecret masterSecret "s ap traffic" finishedHash
  let clientApplicationSecret :=
    TLS13.KeySchedule.deriveSecret masterSecret "c ap traffic" finishedHash
  let exporterMasterSecret :=
    TLS13.KeySchedule.deriveSecret masterSecret "exp master" finishedHash
  let serverApplicationKeys ← liftRecord (Record.deriveTrafficKeys serverApplicationSecret)
  let clientApplicationKeys ← liftRecord (Record.deriveTrafficKeys clientApplicationSecret)

  -- Seal EE‖Cert‖CertVerify‖Finished as protected handshake, after the
  -- plaintext ServerHello (and a compatibility CCS when the client used a
  -- nonempty legacy session id).
  let flight := encryptedExtensions.encoded ++ requestBytes ++ certificate.encoded
    ++ certVerify.encoded ++ serverFinished.encoded
  let (_, sealedFlight) ←
    sealHandshakeFlight serverWriteKeys flight 0 ByteArray.empty
  let serverHelloWire ← liftRecord (Record.encodePlaintext .handshake serverHello.encoded)
  let sendCompatibilityCcs :=
    !hello.legacySessionId.isEmpty && !state.compatibilityCcsSent
  let ccsWire ←
    if !sendCompatibilityCcs then
      pure ByteArray.empty
    else
      liftRecord (Record.encodePlaintext .changeCipherSpec (ByteArray.empty.push 1))
  let wireBytes := serverHelloWire ++ ccsWire ++ sealedFlight

  pure ({
    state with
    phase := .waitingClientFinished
    handshakeBuffered := ByteArray.empty
    transcript
    x25519Private := ByteArray.empty
    p256Private := none
    signingKey := ByteArray.empty
    certificateChain := #[]
    readKeys? := some clientReadKeys
    writeKeys? := some serverApplicationKeys
    sendingKeyUpdates := 0
    clientApplicationKeys? := some clientApplicationKeys
    expectedClientFinished? := some expectedClientFinished
    exporterMasterSecret? := some exporterMasterSecret
    masterSecret? := some masterSecret
    clientHandshakeSecret? := if state.clientAuth.isSome then some clientHandshakeSecret else none
    alpnSelected := alpnSelected
    peerServerName := hello.serverName
    cipherSuiteSelected := some Handshake.tlsChaCha20Poly1305Sha256
    groupSelected := some group
    retryGroup? := none
    retryHello? := none
    compatibilityCcsSent := state.compatibilityCcsSent || sendCompatibilityCcs
    clientOffersPostHandshakeAuth := hello.extensions.any
      (·.extensionType == Handshake.postHandshakeAuthExtension)
  }, wireBytes)

/-! ## Session tickets and resumption (RFC 9846 §2.2, §4.2.11, §4.6.1)

A ticket is this server's own sealed record of the session: ChaCha20-Poly1305
under `ticketKey`, with a fresh 12-byte nonce in front, over the PSK, the
ticket_age_add, the issue time and the lifetime. Nothing is stored server side,
and a ticket this server did not seal fails authentication and is ignored. -/

private def beBytes (n width : Nat) : ByteArray :=
  ByteArray.mk ((List.range width).map fun i => UInt8.ofNat (n >>> (8 * (width - 1 - i)))).toArray

private def beNat (bytes : ByteArray) : Nat :=
  bytes.foldl (fun acc b => acc * 256 + b.toNat) 0

private def ticketAad : ByteArray := "tls13-lean ticket v1".toUTF8

/-- What a sealed ticket carries. -/
structure TicketContents where
  psk : ByteArray
  ageAdd : UInt32
  issuedMs : Nat
  lifetime : UInt32

private def sealTicket (key sealNonce : ByteArray) (contents : TicketContents) : ByteArray :=
  let plaintext := ByteArray.mk #[1] ++ contents.psk ++ beBytes contents.ageAdd.toNat 4 ++
    beBytes contents.issuedMs 8 ++ beBytes contents.lifetime.toNat 4
  sealNonce ++ HaclStar.ChaCha20Poly1305.encrypt key sealNonce ticketAad plaintext

/-- Open a ticket this server sealed, or `none`. -/
def openTicket (key identity : ByteArray) : Option TicketContents :=
  if identity.size != 12 + 49 + 16 then none
  else
    match HaclStar.ChaCha20Poly1305.decrypt key (identity.extract 0 12) ticketAad
        (identity.extract 12 identity.size) with
    | none => none
    | some plain =>
      if plain.size == 49 && plain.get! 0 == 1 then
        some { psk := plain.extract 1 33
               ageAdd := UInt32.ofNat (beNat (plain.extract 33 37))
               issuedMs := beNat (plain.extract 37 45)
               lifetime := UInt32.ofNat (beNat (plain.extract 45 49)) }
      else none

/-- A ticket is live from its issue time for its lifetime. -/
private def ticketLive (state : State) (ticket : TicketContents) : Bool :=
  ticket.issuedMs ≤ state.nowMs && state.nowMs - ticket.issuedMs ≤ ticket.lifetime.toNat * 1000

/-- The PSK to resume with, as `(identity index, PSK)`: the first offered
ticket this server sealed that is still live. Its binder, the HMAC under the
`res binder` key over the transcript before this ClientHello and the
ClientHello truncated before its binders, must verify, or the handshake fails
with decrypt_error. `none` means a full handshake: no ticket key, a ClientHello
that offers no PSK or not psk_dhe_ke, client authentication required (a ticket
does not record a client identity), or no ticket that opens. -/
def choosePsk (state : State) (hello : Handshake.ClientHello)
    (beforeHello : ByteArray) : Except Error (Option (Nat × ByteArray)) := do
  let offered ← liftHandshake hello.offeredPsks
  let some offered := offered | pure none
  let modes ← liftHandshake hello.pskModes
  let some modes := modes
    | throw (.missingRequiredExtension Handshake.pskKeyExchangeModesExtension)
  let some key := state.ticketKey | pure none
  if state.clientAuth.isSome || !modes.toList.contains Handshake.pskDheKe then
    return none
  let candidates := (List.range offered.identities.size).filterMap fun i =>
    (openTicket key offered.identities[i]!.1).bind fun ticket =>
      if ticketLive state ticket then some (i, ticket) else none
  let some (index, ticket) := candidates.head? | pure none
  let binderKey := TLS13.KeySchedule.binderKey (TLS13.KeySchedule.earlySecret ticket.psk)
    emptyTranscriptHash
  let truncated := Handshake.truncatedClientHello hello.encoded offered.bindersLength
  let expected := finishedVerifyData binderKey (HaclStar.sha256 (beforeHello ++ truncated))
  unless constantTimeEq expected offered.binders[index]! do
    throw .pskBinderMismatch
  pure (some (index, ticket.psk))

/-- The resumed handshake (RFC 9846 §2.2): `completeClientHello` with the Early
Secret keyed by the ticket's PSK, pre_shared_key in the ServerHello, and no
CertificateRequest, Certificate or CertificateVerify, since the PSK
authenticates the server. The (EC)DHE exchange still runs (psk_dhe_ke). -/
def completePskClientHello (state : State) (hello : Handshake.ClientHello)
    (group : Handshake.NamedGroup) (transcriptPrefix : ByteArray)
    (selectedIdentity : Nat) (psk : ByteArray) :
    Except Error (State × ByteArray) := do
  let (serverPublic, sharedSecret) ← keyExchange state hello group
  unless sharedSecret.size == TLS13.KeySchedule.hashLen do
    throw (.internalState s!"ECDHE returned a {sharedSecret.size}-byte shared secret")
  let serverHello ← liftHandshake
    (Handshake.encodeServerHelloPsk state.serverRandom hello.legacySessionId group
      serverPublic selectedIdentity)
  let earlySecret := TLS13.KeySchedule.earlySecret psk
  let handshakeSecret :=
    TLS13.KeySchedule.handshakeSecret earlySecret sharedSecret emptyTranscriptHash
  let transcript := transcriptPrefix ++ serverHello.encoded
  let serverHelloHash := HaclStar.sha256 transcript
  let clientHandshakeSecret :=
    TLS13.KeySchedule.deriveSecret handshakeSecret "c hs traffic" serverHelloHash
  let serverHandshakeSecret :=
    TLS13.KeySchedule.deriveSecret handshakeSecret "s hs traffic" serverHelloHash
  let serverWriteKeys ← liftRecord (Record.deriveTrafficKeys serverHandshakeSecret)
  let clientReadKeys ← liftRecord (Record.deriveTrafficKeys clientHandshakeSecret)
  let alpnSelected := selectAlpn state.alpnProtocols hello.alpnProtocols
  let encryptedExtensions ← liftHandshake (Handshake.encodeEncryptedExtensions alpnSelected)
  let transcript := transcript ++ encryptedExtensions.encoded
  let serverVerifyData := finishedVerifyData serverHandshakeSecret (HaclStar.sha256 transcript)
  let serverFinished ← liftHandshake (Handshake.encodeFinished serverVerifyData)
  let transcript := transcript ++ serverFinished.encoded
  let finishedHash := HaclStar.sha256 transcript
  let expectedClientFinished := finishedVerifyData clientHandshakeSecret finishedHash
  let masterSecret := TLS13.KeySchedule.masterSecret handshakeSecret emptyTranscriptHash
  let serverApplicationSecret :=
    TLS13.KeySchedule.deriveSecret masterSecret "s ap traffic" finishedHash
  let clientApplicationSecret :=
    TLS13.KeySchedule.deriveSecret masterSecret "c ap traffic" finishedHash
  let exporterMasterSecret :=
    TLS13.KeySchedule.deriveSecret masterSecret "exp master" finishedHash
  let serverApplicationKeys ← liftRecord (Record.deriveTrafficKeys serverApplicationSecret)
  let clientApplicationKeys ← liftRecord (Record.deriveTrafficKeys clientApplicationSecret)
  let flight := encryptedExtensions.encoded ++ serverFinished.encoded
  let (_, sealedFlight) ←
    sealHandshakeFlight serverWriteKeys flight 0 ByteArray.empty
  let serverHelloWire ← liftRecord (Record.encodePlaintext .handshake serverHello.encoded)
  let sendCompatibilityCcs :=
    !hello.legacySessionId.isEmpty && !state.compatibilityCcsSent
  let ccsWire ←
    if !sendCompatibilityCcs then
      pure ByteArray.empty
    else
      liftRecord (Record.encodePlaintext .changeCipherSpec (ByteArray.empty.push 1))
  let wireBytes := serverHelloWire ++ ccsWire ++ sealedFlight
  pure ({
    state with
    phase := .waitingClientFinished
    handshakeBuffered := ByteArray.empty
    transcript
    x25519Private := ByteArray.empty
    p256Private := none
    signingKey := ByteArray.empty
    certificateChain := #[]
    readKeys? := some clientReadKeys
    writeKeys? := some serverApplicationKeys
    sendingKeyUpdates := 0
    clientApplicationKeys? := some clientApplicationKeys
    expectedClientFinished? := some expectedClientFinished
    exporterMasterSecret? := some exporterMasterSecret
    masterSecret? := some masterSecret
    clientHandshakeSecret? := none
    alpnSelected := alpnSelected
    peerServerName := hello.serverName
    cipherSuiteSelected := some Handshake.tlsChaCha20Poly1305Sha256
    groupSelected := some group
    retryGroup? := none
    retryHello? := none
    compatibilityCcsSent := state.compatibilityCcsSent || sendCompatibilityCcs
    resumed := true
    clientOffersPostHandshakeAuth := hello.extensions.any
      (·.extensionType == Handshake.postHandshakeAuthExtension)
  }, wireBytes)

/-- Resume when the ClientHello offers a ticket this server accepts
(`choosePsk`), else run the full handshake. `beforeHello` is the transcript
before this ClientHello (empty, or message_hash and the HelloRetryRequest), and
`transcriptPrefix` the transcript through it. -/
private def completeHello (state : State) (hello : Handshake.ClientHello)
    (group : Handshake.NamedGroup) (beforeHello transcriptPrefix : ByteArray) :
    Except Error (State × ByteArray) := do
  match ← choosePsk state hello beforeHello with
  | none => completeClientHello state hello group transcriptPrefix
  | some (index, psk) =>
    completePskClientHello state hello group transcriptPrefix index psk

/-- Emit one RFC 8446 HelloRetryRequest and replace CH1 in the transcript with
its synthetic message_hash. No handshake keys exist at this point. -/
def sendHelloRetryRequest (state : State) (message : Handshake.Message)
    (hello : Handshake.ClientHello) (group : Handshake.NamedGroup) :
    Except Error (State × ByteArray) := do
  let retry ← liftHandshake
    (Handshake.encodeHelloRetryRequest hello.legacySessionId group)
  let messageHash ← liftHandshake
    (Handshake.frame Handshake.messageHashType (HaclStar.sha256 message.encoded))
  let retryWire ← liftRecord (Record.encodePlaintext .handshake retry.encoded)
  let sendCompatibilityCcs := !hello.legacySessionId.isEmpty
  let ccsWire ←
    if sendCompatibilityCcs then
      liftRecord (Record.encodePlaintext .changeCipherSpec (ByteArray.empty.push 1))
    else
      pure ByteArray.empty
  pure ({
    state with
    phase := .waitingSecondClientHello
    handshakeBuffered := ByteArray.empty
    transcript := messageHash.encoded ++ retry.encoded
    retryGroup? := some group
    retryHello? := some hello
    cipherSuiteSelected := some Handshake.tlsChaCha20Poly1305Sha256
    groupSelected := some group
    compatibilityCcsSent := sendCompatibilityCcs
  }, retryWire ++ ccsWire)

/-- Process an initial or retry ClientHello. The first may produce HRR; a
second HRR is forbidden and a malformed CH2 fails with illegal_parameter. -/
private def acceptClientHello (state : State) (message : Handshake.Message) :
    Except Error (State × ByteArray) := do
  let hello ← liftHandshake (Handshake.parseClientHello message)
  checkConfig state
  checkCommonOffers hello state.signingAlgorithm.scheme
  match state.phase with
  | .waitingClientHello =>
      let group ← selectGroup state hello
      if (clientShare? hello group).isSome then
        completeHello state hello group ByteArray.empty message.encoded
      else
        sendHelloRetryRequest state message hello group
  | .waitingSecondClientHello =>
      let some group := state.retryGroup?
        | throw (.internalState "retry phase has no requested group")
      let some first := state.retryHello?
        | throw (.internalState "retry phase has no first ClientHello")
      checkRetryClientHello first hello group
      completeHello state hello group state.transcript (state.transcript ++ message.encoded)
  | phase =>
      throw (.internalState s!"acceptClientHello called while waiting for {phase.render}")

def acceptClientFinished (state : State) (message : Handshake.Message) :
    Except Error State := do
  let finished ← liftHandshake (Handshake.parseFinished message)
  let some expected := state.expectedClientFinished?
    | throw (.internalState "missing expected client Finished")
  unless constantTimeEq expected finished.verifyData do
    throw .clientFinishedMismatch
  let some clientApplicationKeys := state.clientApplicationKeys?
    | throw (.internalState "missing client application keys")
  if state.clientAuth.isSome then
    unless state.clientCertificateReceived && state.clientCertificateVerified do
      throw .clientCertificateRequired
  pure {
    state with
    phase := .connected
    handshakeBuffered := ByteArray.empty
    readKeys? := some clientApplicationKeys
    clientApplicationKeys? := none
    expectedClientFinished? := none
    clientHandshakeSecret? := none
    clientAuth := none
    -- RFC 9846 §7.1: resumption_master_secret binds ClientHello…client Finished.
    resumptionMasterSecret? := state.masterSecret?.map fun master =>
      TLS13.KeySchedule.deriveSecret master "res master"
        (HaclStar.sha256 (state.transcript ++ message.encoded))
    masterSecret? := none
    handshakeTranscript :=
      if state.clientOffersPostHandshakeAuth && state.postHandshakeAuth.isSome then
        state.transcript ++ message.encoded
      else ByteArray.empty
    transcript := ByteArray.empty
    pendingClientCertificates := #[]
  }

/-! ## Post-handshake and alerts (role-symmetric). -/

/-- Strict two-message client authentication; no certificate identity becomes
observable until both path validation and proof of possession succeed. -/
private def acceptClientAuthentication (state : State) (message : Handshake.Message) :
    Except Error State := do
  let some policy := state.clientAuth
    | throw (.unexpectedHandshake state.phase message.msgType)
  let some secret := state.clientHandshakeSecret?
    | throw (.internalState "missing client handshake secret")
  let transcript := state.transcript ++ message.encoded
  let expected := finishedVerifyData secret (HaclStar.sha256 transcript)
  if !state.clientCertificateReceived then
    unless message.msgType == Handshake.certificateType do
      throw (.unexpectedHandshake state.phase message.msgType)
    unless message.body.size ≤ policy.maximumCertificateBytes do
      throw .badClientCertificate
    let entries ← liftHandshake
      (Handshake.parseClientCertificate message state.certificateRequestContext)
    unless entries.size ≤ policy.maximumCertificates do
      throw .badClientCertificate
    if entries.isEmpty then
      if policy.required then throw .clientCertificateRequired
      pure { state with
        transcript
        expectedClientFinished? := some expected
        clientCertificateReceived := true
        clientCertificateVerified := true }
    else
      let certificates ← match entries.mapM (fun entry => TLS13.X509.Certificate.decode entry.der) with
        | .ok certificates => pure certificates
        | .error _ => throw .badClientCertificate
      let leaf := certificates[0]!
      unless TLS13.X509.Signature.certificateVerifySchemeCompatible .ed25519
          leaf.tbsCertificate.subjectPublicKeyInfo do
        throw .badClientCertificate
      let _ ← match TLS13.X509.Chain.validate policy.now leaf
          (certificates.extract 1 certificates.size) policy.trustStore
          10 128 .clientAuth policy.requireExplicitPurpose with
        | .ok verified => pure verified
        | .error _ => throw .badClientCertificate
      pure { state with
        transcript
        expectedClientFinished? := some expected
        clientCertificateReceived := true
        pendingClientCertificates := certificates }
  else
    unless !state.clientCertificateVerified &&
        message.msgType == Handshake.certificateVerifyType do
      throw (.unexpectedHandshake state.phase message.msgType)
    let verify ← liftHandshake (Handshake.parseCertificateVerify message)
    let some leaf := state.pendingClientCertificates[0]?
      | throw .badClientCertificate
    unless verify.algorithm == Handshake.ed25519 &&
        TLS13.X509.Signature.verifyClientCertificateVerify
          leaf.tbsCertificate.subjectPublicKeyInfo (HaclStar.sha256 state.transcript)
          verify.signature do
      throw .clientCertificateVerifyFailed
    pure { state with
      transcript
      expectedClientFinished? := some expected
      clientCertificateVerified := true
      peerCertificates := state.pendingClientCertificates
      pendingClientCertificates := #[] }

/-- Consume coalesced or fragmented client-auth messages using the same strict
framer as the main engine. Recursion consumes at least one handshake header. -/
private def consumeClientAuthentication (state : State) (buffer : ByteArray) :
    Except Error (State × ByteArray) :=
  match _htake : takeHandshake? buffer with
  | .error e => .error e
  | .ok none => .ok (state, buffer)
  | .ok (some (message, rest)) =>
    if message.msgType == Handshake.finishedType then .ok (state, buffer)
    else do
      let next ← acceptClientAuthentication state message
      consumeClientAuthentication next rest
  termination_by buffer.size
  decreasing_by exact takeHandshake?_size _htake

/-- Authentication parsing may update only the authentication transcript and
identity fields; record epochs and protocol phase remain with the main engine. -/
private def prepareClientFlight (state : State) : Except Error State := do
  if state.phase == .waitingClientFinished && state.clientAuth.isSome then
    let (auth, buffer) ← consumeClientAuthentication state state.handshakeBuffered
    pure { state with
      handshakeBuffered := buffer
      transcript := auth.transcript
      expectedClientFinished? := auth.expectedClientFinished?
      clientCertificateReceived := auth.clientCertificateReceived
      clientCertificateVerified := auth.clientCertificateVerified
      pendingClientCertificates := auth.pendingClientCertificates
      peerCertificates := auth.peerCertificates }
  else if state.phase == .connected then
    match state.postAuth?, state.readKeys? with
    | some pending, some readKeys =>
      -- RFC 9846 §4.6.2: the client answers under its current application
      -- epoch, whose secret keys the Finished it will send.
      let (auth, buffer) ← consumeClientAuthentication { state with
        clientAuth := some pending.policy
        clientHandshakeSecret? := some readKeys.secret
        certificateRequestContext := pending.context
        transcript := pending.transcript
        expectedClientFinished? := pending.expectedFinished?
        clientCertificateReceived := pending.received
        clientCertificateVerified := pending.verified
        pendingClientCertificates := pending.pending
        peerCertificates := pending.peer } state.handshakeBuffered
      pure { state with
        handshakeBuffered := buffer
        postAuth? := some { pending with
          transcript := auth.transcript
          expectedFinished? := auth.expectedClientFinished?
          received := auth.clientCertificateReceived
          verified := auth.clientCertificateVerified
          pending := auth.pendingClientCertificates
          peer := auth.peerCertificates } }
    | _, _ => pure state
  else pure state

/-- The client Finished that completes a post-handshake authentication: it must
match the one expected after the client's Certificate (and CertificateVerify),
which must have been validated. The certificates become the peer's. -/
def acceptPostHandshakeFinished (state : State) (message : Handshake.Message) :
    Except Error State := do
  let finished ← liftHandshake (Handshake.parseFinished message)
  let some pending := state.postAuth?
    | throw (.unexpectedHandshake state.phase message.msgType)
  let some expected := pending.expectedFinished?
    | throw (.unexpectedHandshake state.phase message.msgType)
  unless constantTimeEq expected finished.verifyData do
    throw .clientFinishedMismatch
  unless pending.received && pending.verified do
    throw .clientCertificateRequired
  pure { state with
    postAuth? := none
    peerCertificates := if pending.peer.isEmpty then state.peerCertificates else pending.peer
    postHandshakeAuthentications := state.postHandshakeAuthentications + 1 }

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
  -- RFC 9846 treats AlertLevel as a legacy field: recipients ignore its
  -- value and determine handling from AlertDescription alone.
  if description == 0 then
    if duringHandshake then
      throw .peerClosedDuringHandshake
    else
      pure ({ state with peerClosed := true }, ByteArray.empty)
  else if description == 90 then
    pure (state, ByteArray.empty)
  else
    throw (.peerAlert level description)

/-- RFC 9846 §7.5 keying material exporter, with RFC 5705's interface:
`TLS-Exporter(label, context, length)` from this connection's
`exporter_master_secret`. TLS 1.3 makes an empty context the same as no context.
Available once the client Finished verifies; it reads the state and changes
nothing. -/
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
    let message ← liftHandshake (Handshake.encodeKeyUpdate request)
    let writeKeys ← requireWriteKeys state
    let (advancedKeys, wireBytes) ←
      liftRecord (Record.«seal» writeKeys .handshake message.encoded)
    let updatedKeys ← liftRecord advancedKeys.update
    pure ({
      state with
      writeKeys? := some updatedKeys
      sendingKeyUpdates := state.sendingKeyUpdates + 1
    }, wireBytes)
  else
    -- RFC 9846 requires silently ignoring a reciprocal-update request once
    -- sending another KeyUpdate would exceed the connection-wide limit.
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

/-- Send a NewSessionTicket (RFC 9846 §4.6.1) on an established connection,
under the current write epoch. The ticket carries
`HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, 32)`
sealed under `ticketKey`; the ticket_nonce counts this connection's tickets, so
each carries its own PSK. `ageAdd` and the 12-byte `sealNonce` must be fresh
random values for every ticket, which the caller supplies because the engine
draws no entropy. -/
def issueTicket (state : State) (ageAdd : UInt32) (sealNonce : ByteArray) :
    Except Error Output := do
  unless state.phase == .connected do
    throw (.notConnected state.phase)
  if state.localClosed then
    throw .connectionClosed
  let some key := state.ticketKey
    | throw (.invalidConfig "no ticket key is configured")
  let some resumptionMaster := state.resumptionMasterSecret?
    | throw (.internalState "missing resumption master secret")
  unless sealNonce.size == 12 do
    throw (.invalidConfig s!"ticket seal nonce must be 12 bytes, got {sealNonce.size}")
  let ticketNonce := beBytes state.ticketsIssued 8
  let ticket := sealTicket key sealNonce {
    psk := TLS13.KeySchedule.ticketPsk resumptionMaster ticketNonce
    ageAdd
    issuedMs := state.nowMs
    lifetime := state.ticketLifetime
  }
  let message ← liftHandshake
    (Handshake.encodeNewSessionTicket state.ticketLifetime ageAdd ticketNonce ticket)
  let writeKeys ← requireWriteKeys state
  let (writeKeys, wireBytes) ←
    liftRecord (Record.«seal» writeKeys .handshake message.encoded)
  pure {
    state := { state with writeKeys? := some writeKeys, ticketsIssued := state.ticketsIssued + 1 }
    wireBytes
  }

/-- Ask the client for a certificate after the handshake (RFC 9846 §4.6.2): a
CertificateRequest with a fresh non-empty `context` (at most 255 bytes), under
the current write epoch. The client must have offered post_handshake_auth and
`postHandshakeAuth` must be configured; one request is outstanding at a time.
The answer arrives through `feed`; `postHandshakeAuthentications` counts the
completed ones and `peerCertificates` holds the validated chain. -/
def requestClientCertificate (state : State) (context : ByteArray) :
    Except Error Output := do
  unless state.phase == .connected do
    throw (.notConnected state.phase)
  if state.localClosed then
    throw .connectionClosed
  let some policy := state.postHandshakeAuth
    | throw (.invalidConfig "no post-handshake client authentication policy")
  unless state.clientOffersPostHandshakeAuth && state.postAuth?.isNone &&
      !context.isEmpty && context.size ≤ 255 do
    throw (.invalidConfig "cannot send a post-handshake CertificateRequest now")
  let request ← liftHandshake (Handshake.encodeCertificateRequest context)
  let writeKeys ← requireWriteKeys state
  let (writeKeys, wireBytes) ←
    liftRecord (Record.«seal» writeKeys .handshake request.encoded)
  let pending : PostAuth := {
    policy := policy
    context := context
    transcript := state.handshakeTranscript ++ request.encoded }
  pure {
    state := { state with writeKeys? := some writeKeys, postAuth? := some pending }
    wireBytes
  }




private def invalidKeyUpdateRequest (message : Handshake.Message) : Bool :=
  message.msgType == Handshake.keyUpdateType &&
    message.body.size == 1 &&
    (Handshake.KeyUpdateRequest.ofUInt8? (message.body.get! 0)).isNone

private def parseKeyUpdateForServer (message : Handshake.Message) :
    Except Error Handshake.KeyUpdate :=
  if invalidKeyUpdateRequest message then
    .error (.illegalParameter
      s!"invalid KeyUpdate request value {message.body.get! 0}")
  else
    liftHandshake (Handshake.parseKeyUpdate message)

def acceptKeyUpdate (state : State) (message : Handshake.Message) :
    Except Error (State × ByteArray) := do
  let update ← parseKeyUpdateForServer message
  let readKeys ← requireReadKeys state
  let updatedReadKeys ← liftRecord readKeys.update
  let state := { state with readKeys? := some updatedReadKeys }
  match update.request with
  | .updateNotRequested => pure (state, ByteArray.empty)
  | .updateRequested =>
      if state.localClosed then
        pure (state, ByteArray.empty)
      else
        sendKeyUpdate state

/-! Reduction lemmas used to prove that key updates leave the handshake
buffer untouched, which bounds the `processHandshakeBuffer` recursion. -/

private theorem except_bind_ok {ε α β : Type} (a : α) (f : α → Except ε β) :
    (Except.ok a >>= f) = f a := rfl
private theorem except_bind_error {ε α β : Type} (e : ε)
    (f : α → Except ε β) :
    ((Except.error e : Except ε α) >>= f) = Except.error e := rfl
private theorem except_pure {ε α : Type} (a : α) :
    (pure a : Except ε α) = Except.ok a := rfl

private theorem sendKeyUpdate_buffered {state next : State}
    {wireBytes : ByteArray}
    {request : Handshake.KeyUpdateRequest} (h : sendKeyUpdate state request = .ok (next, wireBytes)) :
    next.handshakeBuffered = state.handshakeBuffered := by
  unfold sendKeyUpdate at h
  split at h
  · cases h1 : liftHandshake (Handshake.encodeKeyUpdate request) with
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
  · cases h
    rfl

private theorem acceptKeyUpdate_buffered {state next : State}
    {message : Handshake.Message} {wireBytes : ByteArray}
    (h : acceptKeyUpdate state message = .ok (next, wireBytes)) :
    next.handshakeBuffered = state.handshakeBuffered := by
  unfold acceptKeyUpdate at h
  cases h1 : parseKeyUpdateForServer message with
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

private def processHandshakeBuffer (state : State) :
    Except Error (State × ByteArray) :=
  match takeHandshake? state.handshakeBuffered with
  | .error e => .error e
  | .ok none => .ok (state, ByteArray.empty)
  | .ok (some (message, rest)) =>
    let state' := { state with handshakeBuffered := rest }
    match state'.phase with
    | .waitingClientHello => do
        unless message.msgType == Handshake.clientHelloType do
          throw (.unexpectedHandshake state'.phase message.msgType)
        unless rest.isEmpty do
          throw .interleavedHandshake
        acceptClientHello { state' with handshakeBuffered := ByteArray.empty }
          message
    | .waitingSecondClientHello => do
        unless message.msgType == Handshake.clientHelloType do
          throw (.unexpectedHandshake state'.phase message.msgType)
        unless rest.isEmpty do
          throw .interleavedHandshake
        acceptClientHello { state' with handshakeBuffered := ByteArray.empty }
          message
    | .waitingClientFinished => do
        unless message.msgType == Handshake.finishedType do
          throw (.unexpectedHandshake state'.phase message.msgType)
        unless rest.isEmpty do
          throw .interleavedHandshake
        let stateF ← acceptClientFinished state' message
        pure (stateF, ByteArray.empty)
    | .connected =>
        if message.msgType == Handshake.finishedType && state'.postAuth?.isSome then do
          unless rest.isEmpty do
            throw .interleavedHandshake
          let stateF ← acceptPostHandshakeFinished state' message
          pure (stateF, ByteArray.empty)
        else if message.msgType == Handshake.keyUpdateType then do
          -- KeyUpdate must be aligned to the end of its protected handshake
          -- record: trailing bytes were decrypted under the old read epoch.
          unless rest.isEmpty do
            throw .interleavedHandshake
          acceptKeyUpdate state' message
        else
          .error (.unexpectedHandshake state'.phase message.msgType)

private def processProtectedRecord (state : State) (record : Record.RawRecord) :
    Except Error (State × ByteArray × ByteArray) := do
  let readKeys ← requireReadKeys state
  let (readKeys, plaintext) ← liftRecord (Record.«open» readKeys record)
  let state := { state with readKeys? := some readKeys }
  if state.phase == .connected && state.peerClosed then
    -- RFC 9846 §6.1: once close_notify has been received, ignore every
    -- later protected message, including another record in this same chunk.
    pure (state, ByteArray.empty, ByteArray.empty)
  else
    match plaintext.contentType with
    | .applicationData =>
        unless state.phase == .connected do
          throw (.unexpectedRecord state.phase plaintext.contentType)
        unless state.handshakeBuffered.isEmpty do
          throw .interleavedHandshake
        pure (state, plaintext.fragment, ByteArray.empty)
    | .handshake =>
        if plaintext.fragment.isEmpty then
          throw (.unexpectedRecord state.phase .handshake)
        let state := { state with handshakeBuffered := state.handshakeBuffered ++ plaintext.fragment }
        let state ← prepareClientFlight state
        let (state, wireBytes) ← processHandshakeBuffer state
        pure (state, ByteArray.empty, wireBytes)
    | .alert =>
        unless state.handshakeBuffered.isEmpty do
          throw .interleavedHandshake
        let duringHandshake := state.phase != .connected
        let (state, wireBytes) ← processAlert state plaintext.fragment duringHandshake
        pure (state, ByteArray.empty, wireBytes)
    | .changeCipherSpec =>
        throw (.unexpectedRecord state.phase plaintext.contentType)

private def feedPlaintextClientHello (state : State) (fragment : ByteArray) :
    Except Error (State × ByteArray) := do
  if fragment.isEmpty then
    throw (.unexpectedRecord state.phase .handshake)
  let state := { state with handshakeBuffered := state.handshakeBuffered ++ fragment }
  processHandshakeBuffer state

private def processRecord (state : State) (record : Record.RawRecord) :
    Except Error (State × ByteArray × ByteArray) := do
  match state.phase with
  | .waitingClientHello =>
      match record.contentType with
      | .handshake =>
          let (state, wireBytes) ← feedPlaintextClientHello state record.fragment
          pure (state, ByteArray.empty, wireBytes)
      | .changeCipherSpec =>
          -- Compatibility CCS is only in-window after a *complete* CH1. If
          -- CH1 and CCS are coalesced, processing CH1 advances the phase
          -- before this record is visited. Reaching this branch therefore
          -- means CCS preceded or interrupted CH1.
          throw (.unexpectedRecord state.phase record.contentType)
      | .alert =>
          unless state.handshakeBuffered.isEmpty do
            throw .interleavedHandshake
          let (state, wireBytes) ← processAlert state record.fragment true
          pure (state, ByteArray.empty, wireBytes)
      | contentType => throw (.unexpectedRecord state.phase contentType)
  | .waitingSecondClientHello =>
      match record.contentType with
      | .handshake =>
          let (state, wireBytes) ← feedPlaintextClientHello state record.fragment
          pure (state, ByteArray.empty, wireBytes)
      | .changeCipherSpec =>
          unless state.handshakeBuffered.isEmpty do
            throw .interleavedHandshake
          unless validCompatibilityChangeCipherSpec record.fragment do
            throw .invalidCompatibilityChangeCipherSpec
          pure (state, ByteArray.empty, ByteArray.empty)
      | .alert =>
          unless state.handshakeBuffered.isEmpty do
            throw .interleavedHandshake
          let (state, wireBytes) ← processAlert state record.fragment true
          pure (state, ByteArray.empty, wireBytes)
      | contentType => throw (.unexpectedRecord state.phase contentType)
  | .waitingClientFinished =>
      match record.contentType with
      | .changeCipherSpec =>
          unless state.handshakeBuffered.isEmpty do
            throw .interleavedHandshake
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
      -- The decoder has already framed this transport chunk, but RFC 9846
      -- §6.1 requires all records after close_notify to be ignored.
      .ok { state, wireBytes, plaintext }
    else
      match processRecord state record with
      | .error error => .error { state, error }
      | .ok (next, cleartext, outbound) =>
          processRecords next rest (plaintext ++ cleartext) (wireBytes ++ outbound)

/-- Incrementally consume transport bytes, retaining the latest advanced state on
failure so an I/O shell can seal a fatal alert under the correct epoch. -/
def feedWithFailure (initial : State) (chunk : ByteArray) : Except Failure Output :=
  if initial.peerClosed then
    .ok { state := initial }
  else
    match liftRecord (initial.decoder.feed chunk) with
    | .error error => .error { state := initial, error }
    | .ok (decoder, records) =>
        processRecords { initial with decoder } records.toList ByteArray.empty
          ByteArray.empty

/-- Consume transport bytes. `wireBytes` carries the server flight (in response to
ClientHello) plus any KeyUpdate/close_notify; `plaintext` is decrypted
application data once connected. -/
def feed (state : State) (chunk : ByteArray) : Except Error Output :=
  (feedWithFailure state chunk).mapError Failure.error

/-! ## Application data. -/

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

private def concatByteArrays (parts : Array ByteArray) : ByteArray := Id.run do
  let total := parts.foldl (fun size part => size + part.size) 0
  let mut out := ByteArray.mk (Array.replicate total 0)
  let mut offset := 0
  for part in parts do
    out := part.copySlice 0 out offset part.size
    offset := offset + part.size
  return out

/-- Protect application bytes, splitting at TLS's 2^14-byte record limit. -/
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
    pure { state := { state with writeKeys? := some writeKeys }, wireBytes := concatByteArrays records }

/-- Send `close_notify` under the current write keys. Idempotent. -/
def closeNotify (state : State) : Except Error Output := do
  unless state.phase == .connected do
    throw (.notConnected state.phase)
  let (state, wireBytes) ← emitCloseNotify state
  pure { state, wireBytes }

/-- Emit a fatal, level-2 alert. Before handshake write keys exist (including
after HRR), the alert is a TLSPlaintext record; after ServerHello it is sealed
under the current write epoch. Callers must discard the connection afterwards. -/
def sealFatalAlert (state : State) (description : UInt8) : Except Error Output := do
  if state.localClosed then
    throw .connectionClosed
  let fragment := ByteArray.mk #[2, description]
  match state.writeKeys? with
  | some writeKeys =>
      let (writeKeys, wireBytes) ← liftRecord (Record.«seal» writeKeys .alert fragment)
      pure {
        state := { state with writeKeys? := some writeKeys, localClosed := true }
        wireBytes
      }
  | none =>
      unless state.phase == .waitingClientHello ||
          state.phase == .waitingSecondClientHello do
        throw (.internalState "missing write keys for fatal alert")
      let wireBytes ← liftRecord (Record.encodePlaintext .alert fragment)
      pure { state := { state with localClosed := true }, wireBytes }

/-! ## Runs

A connection is driven by a sequence of caller operations. `run` folds them
purely, which gives the state-machine laws in `Tls.Server.Laws` a single object
to quantify over — in particular the nonce non-reuse theorem, which is about
everything one run of the engine protects. -/

/-- One caller-driven step of a server connection. -/
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
  /-- Send a NewSessionTicket with a fresh ticket_age_add and seal nonce. -/
  | issueTicket (ageAdd : UInt32) (sealNonce : ByteArray)
  /-- Ask for a client certificate after the handshake. -/
  | requestClientCertificate (context : ByteArray)
  deriving Inhabited

def step (state : State) (op : Op) : Except Error Output :=
  match op with
  | .feed chunk => feed state chunk
  | .send plaintext => sealApplication state plaintext
  | .close => closeNotify state
  | .fatalAlert description => sealFatalAlert state description
  | .keyUpdate requestPeer => updateKeys state requestPeer
  | .issueTicket ageAdd sealNonce => issueTicket state ageAdd sealNonce
  | .requestClientCertificate context => requestClientCertificate state context

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

end Server
end Tls
