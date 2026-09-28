module

public import HaclStar.Hmac
public import HaclStar.Sha256
public import HaclStar.Signature
public import TLS13.X509.Signature

public section

/-!
Deterministic ECDSA P-256 signing (RFC 6979) for TLS 1.3 CertificateVerify.

HACL\* signs with a caller-supplied nonce, and a nonce that repeats across two
messages, or leaks, reveals the private key. The engines take no entropy of
their own, so rather than make a fresh nonce a caller obligation this derives
it from the private key and the message with HMAC-SHA256, RFC 6979 §3.2. The
same (key, message) always yields the same signature, and no two messages
share a nonce except with negligible probability. Only the two existing
HACL\* bindings (HMAC-SHA256 and ECDSA-P256-SHA256 signing) are used, so the
trusted C boundary does not grow.

TLS 1.3 carries the signature as a DER `ECDSA-Sig-Value` (RFC 9846 §4.2.3,
RFC 3279), which `encodeECDSAP256Signature` produces from HACL\*'s fixed-width
`r || s`; `TLS13.X509.Signature.parseECDSAP256Signature` is its inverse.
-/

namespace TLS13
namespace Rfc6979

/-- `n` as a `len`-byte big-endian string (RFC 6979 §2.3.3 `int2octets`). -/
def natToBytes (n len : Nat) : ByteArray :=
  ByteArray.mk ((List.range len).map fun i => UInt8.ofNat (n >>> (8 * (len - 1 - i)))).toArray

/-- A big-endian byte string as a number (`bits2int` for a 256-bit hash and a
256-bit group order, where no bits are dropped). -/
def bytesToNat (bytes : ByteArray) : Nat :=
  bytes.foldl (fun acc b => acc * 256 + b.toNat) 0

/-- P-256's group order `q`. -/
abbrev q : Nat := TLS13.X509.Signature.p256Order

/-- The RFC 6979 §3.2 nonce for P-256 with HMAC-SHA256, from the 32-byte
private scalar and the message HACL\* will hash with SHA-256. Returns the empty
string if 16 candidates all fall outside `[1, q)`, which does not happen except
with negligible probability; the caller then fails to sign rather than sign
with a bad nonce. -/
def nonceP256Sha256 (privateKey message : ByteArray) : ByteArray := Id.run do
  let hmac := HaclStar.hmacSha256
  let x := natToBytes (bytesToNat privateKey % q) 32
  let h := natToBytes (bytesToNat (HaclStar.sha256 message) % q) 32
  let mut v := ByteArray.mk (List.replicate 32 (1 : UInt8)).toArray
  let mut k := ByteArray.mk (List.replicate 32 (0 : UInt8)).toArray
  k := hmac k (v ++ ByteArray.mk #[0] ++ x ++ h)
  v := hmac k v
  k := hmac k (v ++ ByteArray.mk #[1] ++ x ++ h)
  v := hmac k v
  for _ in [0:16] do
    v := hmac k v
    let candidate := bytesToNat v
    if 1 ≤ candidate && candidate < q then
      return v
    k := hmac k (v ++ ByteArray.mk #[0])
    v := hmac k v
  return ByteArray.empty

/-- A DER INTEGER for a non-negative 32-byte big-endian scalar: leading zero
bytes removed, and one zero byte added back when the top bit is set. -/
private def derInteger (scalar : ByteArray) : ByteArray :=
  let digits := (scalar.toList.dropWhile (· == 0))
  let digits := if digits.isEmpty then [0] else digits
  let digits := if digits.head! ≥ 0x80 then 0 :: digits else digits
  ByteArray.mk #[0x02, UInt8.ofNat digits.length] ++ ByteArray.mk digits.toArray

/-- The DER `ECDSA-Sig-Value` for HACL\*'s 64-byte `r || s`. -/
def encodeECDSAP256Signature (rs : ByteArray) : ByteArray :=
  let body := derInteger (rs.extract 0 32) ++ derInteger (rs.extract 32 64)
  ByteArray.mk #[0x30, UInt8.ofNat body.size] ++ body

/-- Sign `message` with ECDSA P-256 / SHA-256 under a 32-byte private scalar,
with the RFC 6979 nonce, returning the DER `ECDSA-Sig-Value`, or `none` if the
key or nonce is out of range. -/
def signP256 (privateKey message : ByteArray) : Option ByteArray :=
  let nonce := nonceP256Sha256 privateKey message
  if nonce.isEmpty then none
  else (HaclStar.Signature.ecdsaP256Sha256Sign privateKey message nonce).map
    encodeECDSAP256Signature

end Rfc6979
end TLS13
