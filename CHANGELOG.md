# Changelog

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
