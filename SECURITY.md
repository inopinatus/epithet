# Epithet security

## Cryptographic considerations

The primary construction is `AES-256-ECB(id(8B) + HMAC-SHA256(id)[0,7])` with the result base58
encoded for transmission and a contextual prefix prepended. Subkeys for AES and HMAC are by default
derived with HKDF using an internal key generator that takes IKM from a passphrase via scrypt,
salting generated keys by prefix and purpose.

This library is intended for high-performance obfuscation of integer sequences, deflection of casual
tampering, and conversion to a compact, stable wire parameter format that is hard to guess and hard
to predict.  Although it uses standard cryptographic primitives to do so, the design trade-off of
the compact format means it is not intended to defeat nation-state security services, talented
cryptographers, or even a well-resourced enterprise.

The identifiers produced are intentionally deterministic i.e. replayable and reusable. For privacy,
confidentiality, and authentication purposes they should therefore be considered equivalent to the
plaintext integer they represent, and those concerns must still be addressed in the usual manner.

The tamper detection is necessarily probabilistic, because the MAC is truncated.

Encodings are canonical, producing exactly one string per id, and Epithet will reject attempts to
decode a value exceeding the 128-bit block.

If configuring alternative cipher algorithms, note that only 128-bit block ciphers that function
without IV/nonce requirements are accepted. Streaming ciphers (e.g. chacha20) or block ciphers in
streaming modes (e.g. aes-256-ctr) must not be used; no nonce/IV value is included in construction,
making them trivially vulnerable to known-plaintext attacks.  These, CBC/OCB, and other IV/nonce
modes may also be rejected by Epithet's guardrails.

If configuring alternative digest algorithms, note that any algorithm may be accepted that produces
at least 64 bits of output.  HMAC does not rest on collision resistance, so even dated digests are
not trivially forgeable here, but algorithms other than the defaults step outside the supported
profile.  If you must stray, stay within the SHA-2 family.

A weak, guessable, or disclosed passphrase will compromise the obfuscation and tamper-detection
properties.

Use Epithet at your own risk.

## On salt

Epithet uses salt in two ways.  Firstly, as part of a scrypt operation to turn the configured
passphrase into initial keying material.  Secondly, to supply an additional affordance to separate
derived subkeys by some application-specific division such as purpose or rotation epoch.  Epithet
does not store or verify passwords; both uses of salt are non-secret configuration and may safely be
committed to source control.

## Vulnerabilities

If you think you've found a vulnerability in Epithet that compromises its design or behaviour, please
[report it via a private advisory](https://github.com/inopinatus/epithet/security/advisories/new).
Do not open a public issue or pull request.
