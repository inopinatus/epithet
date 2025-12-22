# Epithet security

## Cryptographic considerations

The primary construction is `AES-256-ECB(id(8B) + HMAC-SHA256(id)[0,7])` with the result
base58 encoded for transmission and a contextual prefix prepended. Subkeys for AES and
HMAC are by default derived with HKDF using an internal key generator that takes IKM from
a passphrase via scrypt, salting generated keys by prefix and purpose.

This library is intended for high-performance obfuscation of integer sequences, deflection
of casual tampering, and conversion to a compact, stable wire parameter format.  Although
it uses standard cryptographic primitives to do so, the design trade-off of the compact
format means it is not intended to defeat nation-state security services, talented
cryptographers, or even a well-resourced enterprise.

The identifiers produced are intentionally deterministic i.e. replayable and reusable. For
privacy, confidentiality, and authentication purposes they should therefore be considered
equivalent to the plaintext integer they represent, and those purposes must still be addressed
in the usual manner.

The tamper detection is necessarily probabilistic, because the MAC is truncated.

If configuring alternative cipher and digest algorithms, note that only 128-bit block
ciphers that function without IV/nonce requirements are accepted. Streaming ciphers
(e.g. chacha20) or block ciphers in streaming modes (e.g. aes-256-ctr) must not be used;
no nonce/IV value is included in construction, making them trivially vulnerable to
known-plaintext attacks. These, CBC/OCB, and other IV/nonce modes may also be rejected
by Epithet's guardrails.

A weak, guessable, or disclosed passphrase will compromise the obfuscation and
tamper-detection properties.

Use Epithet at your own risk.

## Vulnerabilities

If you think you've found a vulnerability in Epithet that compromises its design or behaviour, please
[report it via a private advisory](https://github.com/inopinatus/epithet/security/advisories/new).
Do not open a public issue or pull request.


