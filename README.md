# Epithet

Epithet generates stable, prefixed Base58 identifiers from 64-bit integers. It uses AES and HMAC to provide reversible obfuscation and tamper detection, while keeping identifiers compact and consistently 22 characters in length.

## Installation

Add to your Gemfile:

```ruby
gem 'epithet'
```

Or install directly:

```bash
gem install epithet
```

## Usage

```ruby
require 'epithet'

def epithet_initialize
  Epithet.configure(
    passphrase: ENV.fetch('EPITHET_PASSPHRASE') { 'example only' },
    salt: 'v1'
  )
end

epithet_initialize
user_epithet = Epithet.new('user')

id = 42
param = user_epithet.encode(id)
# => "user_VsuNnfEYQJJTJYE3n28jaY"

user_epithet.decode(param)
# => 42
```

Configuration at initialisation is recommended, because deriving key material from the passphrase uses scrypt, and is consequently expensive. The `salt:` is optional; it's included when deriving subkey material and may be useful for additional context discrimination or rotation. See the Epithet class for the full set of configuration options.

Note that `decode` returns `nil` when authentication fails and raises ArgumentError on invalid formats.

## Development

Install dependencies and run tests:

```bash
bundle install
rake test
```

## Security considerations

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

Use at your own risk.
