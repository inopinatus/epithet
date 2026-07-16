# Epithet security

## Cryptographic considerations

The primary construction is `AES-256-ECB(id(8B) + MSB_64(HMAC-SHA256(id)))` with the result base58
encoded for transmission and a contextual prefix prepended.  Subkeys for AES and HMAC are by default
derived with HKDF using an internal key generator that takes IKM from a passphrase via scrypt,
salting generated keys by prefix and context.

This library is intended for high-performance obfuscation of integer sequences, deflection of casual
tampering, and conversion to a compact, stable wire parameter format that is hard to guess and hard
to predict.  Although it uses standard cryptographic primitives to do so, the design trade-off of
the compact format means it is not intended to defeat nation-state security services, talented
cryptographers, or even a well-resourced enterprise.

The identifiers produced are intentionally deterministic i.e. replayable and reusable.  For privacy,
confidentiality, and authentication purposes they should therefore be considered equivalent to the
plaintext integer they represent, and those concerns must still be addressed in the usual manner.

The tamper detection is necessarily probabilistic, because the MAC is truncated.  After N
independent forgery attempts, expected success is approximately (N/2^{64}).  This is below the
threshold recommended in RFC 2104 §5 for message authentication.  To be clear, just because an
epithet decodes correctly does not mean it should be used as an authentication token.

Encodings are canonical, producing exactly one string per id, and Epithet will reject attempts to
decode a value exceeding the 128-bit block.

If configuring alternative cipher algorithms, note that only 128-bit block ciphers that function
without IV/nonce requirements are accepted.  Streaming ciphers (e.g. chacha20) or block ciphers in
streaming modes (e.g. aes-256-ctr) must not be used; no nonce/IV value is included in construction,
making them trivially vulnerable to known-plaintext attacks.  These, CBC/OCB, and other IV/nonce
modes may also be rejected by Epithet's guardrails.

If configuring alternative digest algorithms, note that any algorithm may be accepted that produces
at least 64 bits of output.  HMAC does not rest on collision resistance, so even dated digests are
not trivially forgeable here, but algorithms other than the defaults step outside the supported
profile.  If you must stray, we recommend staying within the SHA-2 family.

A weak, guessable, or disclosed passphrase will compromise the obfuscation and tamper-detection
properties.

Use Epithet at your own risk.

## On seasoning

Epithet uses salt in two ways.  Firstly, if the default key generator is in use, as part of the
setup-time scrypt operation turning the configured passphrase into initial keying material.
Secondly, for the HKDF extract phase to separate derived subkeys by some application-specific
division such as purpose or rotation epoch.

To avoid confusing the two uses, the HKDF salt is not referred to directly in Epithet's public API,
and is instead derived from the context and prefix parameters that are documented instead.

Epithet does not store or verify passwords; the scrypt salt, and the context & prefix parameters
used in the HKDF salt, are non-secret configuration and may be safely committed to source control.

## On rotation

This gem provides a deterministic primitive; managing lifecycle, policy, and application-aware
responses to legacy identifiers is intentionally left to framework/application-specific adapters.
When implementing an adapter, the context parameter is recommended as the basis for key rotation.

## Startup cost

Turning a passphrase into initial keying material is intrinsically expensive.  The default scrypt
parameters (N=2^17, r=8) cost roughly 128 MiB of peak memory and a fraction of a second of CPU.
When deployed as indicated this is a boot-time cost, incurred once per configuration rather than
per encode/decode, but budget for it in memory-constrained deployments.

## Vulnerabilities

If you think you've found a vulnerability in Epithet that compromises its design or behaviour, please
[report it via a private advisory](https://github.com/inopinatus/epithet/security/advisories/new).
Do not open a public issue or pull request.
