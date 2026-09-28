module

public import HaclStar.Hkdf
public import HaclStar.Sha256

public section

/-!
TLS 1.3 key schedule (RFC 8446 §7.1), for SHA-256 cipher suites.

The cryptographic core is HKDF-Extract/Expand (`HaclStar.Hkdf`); this module
adds the pure-Lean labelled-derivation layer on top: `HKDF-Expand-Label`,
`Derive-Secret`, and the extract steps that chain the Early / Handshake /
Master secrets. Everything here is a total function of its inputs — the state
machine that sequences these calls with real handshake transcripts lives above.
-/

namespace TLS13
namespace KeySchedule

open HaclStar

/-- Output length of the suite hash (SHA-256), in bytes. -/
def hashLen : Nat := 32

/-- The all-zero HashLen-byte string — TLS 1.3's `0` for a secret-sized value
(the default salt and the no-PSK / no-(EC)DHE inputs). -/
def zeros : ByteArray :=
  ByteArray.mk ((List.replicate hashLen (0 : UInt8)).toArray)

private def u16be (n : Nat) : ByteArray :=
  ByteArray.mk #[UInt8.ofNat (n >>> 8), UInt8.ofNat n]

/-- The `HkdfLabel` structure serialized per RFC 8446 §7.1:
`length` (uint16), then `"tls13 " ++ label` and `context`, each with a one-byte
length prefix. `label` is expected to be ≤ 249 bytes and `context` ≤ 255. -/
def hkdfLabel (length : Nat) (label context : ByteArray) : ByteArray :=
  let full := "tls13 ".toUTF8 ++ label
  u16be length
    ++ ByteArray.mk #[UInt8.ofNat full.size] ++ full
    ++ ByteArray.mk #[UInt8.ofNat context.size] ++ context

/-- `HKDF-Expand-Label(secret, label, context, length)`. -/
def expandLabel (secret : ByteArray) (label : String) (context : ByteArray)
    (length : Nat) : ByteArray :=
  Hkdf.expandSha256 secret (hkdfLabel length label.toUTF8 context) (UInt32.ofNat length)

/-- `Derive-Secret(secret, label, transcriptHash)` — `HKDF-Expand-Label` with the
transcript hash as context and the hash length as the output length. The caller
passes the already-computed transcript hash (SHA-256 of the handshake messages),
so this stays independent of transcript bookkeeping. -/
def deriveSecret (secret : ByteArray) (label : String) (transcriptHash : ByteArray) : ByteArray :=
  expandLabel secret label transcriptHash hashLen

/-- Early Secret = `HKDF-Extract(0, PSK)`. With no pre-shared key, `psk` is the
all-zero string, giving RFC 8448's `33ad0a1c…`. -/
def earlySecret (psk : ByteArray := zeros) : ByteArray :=
  Hkdf.extractSha256 zeros psk

/-- Handshake Secret = `HKDF-Extract(Derive-Secret(Early, "derived", ""), (EC)DHE)`.
`ecdheSecret` is the X25519 shared secret; `emptyHash` is SHA-256 of the empty
string (the transcript hash used by the "derived" step). -/
def handshakeSecret (early ecdheSecret emptyHash : ByteArray) : ByteArray :=
  Hkdf.extractSha256 (deriveSecret early "derived" emptyHash) ecdheSecret

/-- Master Secret = `HKDF-Extract(Derive-Secret(Handshake, "derived", ""), 0)`. -/
def masterSecret (handshake emptyHash : ByteArray) : ByteArray :=
  Hkdf.extractSha256 (deriveSecret handshake "derived" emptyHash) zeros

/-- RFC 9846 §4.6.1: the PSK a NewSessionTicket with this nonce stands for. -/
def ticketPsk (resumptionMasterSecret ticketNonce : ByteArray) : ByteArray :=
  expandLabel resumptionMasterSecret "resumption" ticketNonce hashLen

/-- The resumption binder key (RFC 9846 §7.1): `Derive-Secret(Early Secret,
"res binder", "")`. -/
def binderKey (early emptyHash : ByteArray) : ByteArray :=
  deriveSecret early "res binder" emptyHash

/-- Why an exporter request cannot be served, or `none` when it can. The
application's label becomes the `Label` of an `HkdfLabel`, whose
`"tls13 " + Label` is an `opaque<7..255>`, so it may be at most 249 bytes; and
HKDF-Expand yields at most `255 * Hash.length` bytes. -/
def exporterRequestError? (label : ByteArray) (length : Nat) : Option String :=
  if label.size > 249 then
    some s!"exporter label is {label.size} bytes; at most 249 are allowed"
  else if length > 255 * hashLen then
    some s!"exporter length {length} exceeds HKDF's {255 * hashLen}-byte limit"
  else
    none

/-- RFC 9846 §7.5 `TLS-Exporter(label, context_value, key_length)` from an
exporter master secret. The caller passes `Hash("")` and `Hash(context_value)`;
`label` is the application's exporter label as bytes, used as the label of the
first, `Derive-Secret` step. -/
def exporter (secret label emptyHash contextHash : ByteArray) (length : Nat) :
    ByteArray :=
  let derived := Hkdf.expandSha256 secret (hkdfLabel hashLen label emptyHash)
    (UInt32.ofNat hashLen)
  expandLabel derived "exporter" contextHash length

end KeySchedule
end TLS13
