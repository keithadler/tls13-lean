import Lake
open Lake DSL

/-!
IDE project model. Bazel remains the authoritative build because it compiles
and links the HACL* C shim; these libraries let sibling Lean projects resolve
the protocol and binding declarations in `lake serve`.
-/

package «tls13-lean» where
  leanOptions := #[⟨`experimental.module, true⟩]

@[default_target]
lean_lib «HaclStar» where
  roots := #[
    `HaclStar.Aead,
    `HaclStar.Curve25519,
    `HaclStar.Hex,
    `HaclStar.Hkdf,
    `HaclStar.Hmac,
    `HaclStar.P256,
    `HaclStar.Sha256,
    `HaclStar.Signature,
  ]

@[default_target]
lean_lib «TLS13» where
  roots := #[
    `TLS13.KeySchedule,
    `TLS13.KeySchedule.Refinement,
    `TLS13.KeySchedule.Spec,
    `TLS13.X509,
  ]

@[default_target]
lean_lib «Tls» where
  roots := #[
    `Tls.Record,
    `Tls.Record.Laws,
    `Tls.Handshake,
    `Tls.Identity,
    `Tls.Client,
    `Tls.Client.Laws,
    `Tls.Server,
    `Tls.Server.Laws,
  ]

/-!
Optional native test build, for machines without Bazel and Nix.

`lake build -K hacl=<hacl-star>/dist <test>` compiles the two C shims and the
same fifteen HACL\* translation units `third_party/hacl/hacl.BUILD` lists, then
links the test executables below. Point `hacl` at the `dist` directory of the
archive `MODULE.bazel` pins (commit `504c2987…`, sha256 `e32f7add…`). Without
`-K hacl`, none of this is declared and the lakefile stays the IDE model above;
Bazel remains the authoritative build.
-/

meta if (get_config? hacl).isSome then do
  extern_lib «tls13hacl» pkg := do
    let dist : System.FilePath := (get_config? hacl).getD ""
    let gcc := dist / "gcc-compatible"
    let includes := #[
      "-I", (← getLeanIncludeDir).toString,
      "-I", gcc.toString,
      "-I", (dist / "karamel" / "include").toString,
      "-I", (dist / "karamel" / "krmllib" / "dist" / "minimal").toString]
    let flags := #["-O2", "-fPIC", "-Wno-unused-parameter",
      "-Wno-unused-but-set-variable"]
    -- The fifteen translation units of third_party/hacl/hacl.BUILD.
    let hacl := #[
      "Hacl_Hash_SHA2", "Hacl_HMAC", "Hacl_HKDF", "Hacl_Curve25519_51",
      "Hacl_Ed25519", "Hacl_P256", "Hacl_AEAD_Chacha20Poly1305", "Hacl_Chacha20",
      "Hacl_MAC_Poly1305", "Hacl_Hash_Blake2b", "Hacl_Hash_Blake2s",
      "Hacl_Hash_MD5", "Hacl_Hash_SHA1", "Hacl_Hash_SHA3", "Lib_Memzero0"]
    let mut objects := #[]
    for name in hacl do
      let src ← inputTextFile (gcc / s!"{name}.c")
      objects := objects.push <|
        ← buildO (pkg.buildDir / "hacl" / s!"{name}.o") src includes flags "cc"
    for name in #["hacl_shim", "signature_shim"] do
      let src ← inputTextFile (pkg.dir / "HaclStar" / "shim" / s!"{name}.c")
      objects := objects.push <|
        ← buildO (pkg.buildDir / "shim" / s!"{name}.o") src includes flags "cc"
    buildStaticLib (pkg.staticLibDir / nameToStaticLib "tls13hacl") objects
  lean_exe hacl_kat_test where root := `Test.HaclKat
  lean_exe tls_handshake_test where root := `Test.TlsHandshakeTest
  lean_exe tls_record_test where root := `Test.TlsRecordTest
  lean_exe tls_server_interop_test where root := `Test.TlsServerInteropTest
  lean_exe workload_identity_test where root := `Test.WorkloadIdentityTest
  lean_exe x509_der_test where root := `Test.X509DerTest
  lean_exe x509_certificate_test where root := `Test.X509CertificateTest
  lean_exe x509_chain_test where root := `Test.X509ChainTest
  lean_exe x509_signature_test where root := `Test.X509SignatureTest
  lean_exe x509_hostname_test where root := `Test.X509HostnameTest
  lean_exe x509_channel_binding_test where root := `Test.X509ChannelBindingTest
  lean_exe tls_external_server where root := `Test.TlsExternalServer
