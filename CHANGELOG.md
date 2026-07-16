# Changelog

## Unreleased

### Breaking changes

- The subkey-derivation option `context:` replaces `salt:`, to avoid confusion with scrypt's salt parameter.
- Nil and empty-string prefixes now yield bare params with no separator.
- Config no longer exposes the alphabet string, it carries the Block58 codec around instead.

### Other changes

- Decode stringifies its input, reads it as bytes whatever its encoding
- We now raise Epithet::FormatError (ArgumentError subclass) on invalid wire format
- Validate the alphabet when a Config is created, instead of at Epithet instantiation
- Friendlier error when keygen: is supplied together with passphrase: or scrypt:
- Documentation improvements

## 1.1.0 - 2026-07-14

- Freeze config strings upon object initialization
- Merge custom scrypt params
- Block58 now defaults to a generic s2i that handles any block size
- Optimised 16-byte unrolled s2i selected via `Block58::build`
- Recognize unprefixed decodes by payload length
- Fix github CI warnings
- Write notes on salt & improve examples

## 1.0.0 - 2026-07-14

### Breaking changes

- Treat out-of-range base58 strings as invalid instead of wrapping them.
- Reject separators that share codepoints with the encoding alphabet.
- Drop support for Rubies < 3.3.

### Other changes

- Code style nitpicks.
- Support for 32-bit Rubies.
- Support for Ruby 4.0.
- Documentation improvements.
- A custom alphabet may be configured via `Epithet::Config`.
- Custom alphabets must be strictly ascending byte codepoints.

## 0.1.0 - 2025-12-22
- Initial release.
