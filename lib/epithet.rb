# frozen_string_literal: true

require 'epithet/version'
require 'openssl'
require 'epithet/scrypt'
require 'epithet/keygen'
require 'epithet/block58'
require 'epithet/config'

#
# Epithet, a tool for external identifiers.
#
# Given a 64-bit value such as a database sequence ID, and a context-specific
# prefix (typically a model or table name), produces a replayable string parameter of
# consistent length, with modest obfuscation and authentication properties.
#
# Pseudo-AEAD is via `AES-256-ECB(id(8B) + MSB_64(HMAC-SHA256(id)))` with the result
# base58 encoded for transmission and the contextual prefix prepended.
#
# Encodings are canonical; a given configuration produces exactly one string per id.
#
# Subkeys for AES and HMAC are by default derived with HKDF using an internal key
# generator that takes IKM from a passphrase via scrypt.  An alternative key generator
# may be injected via Config objects.  Subkeys are salted by prefix and an optional
# context string, which may be useful for purpose separation or rotation, and each
# subkey is bound to the configured name of the algorithm that consumes it.
#
# Example usage:
#
#     # in setup-environment.sh
#     EPITHET_PASSPHRASE='example_only' ; export EPITHET_PASSPHRASE
#
#     # ... later, in Ruby ...
#     Epithet.configure(passphrase: ENV.fetch('EPITHET_PASSPHRASE'))
#     user_epithet = Epithet.new('user')
#     user_epithet.encode(1) #=> "user_NEwRoiarS9wdmiLmjEtti3"
#
class Epithet
  # Raised by #decode when the input is not valid wire format.
  FormatError = Class.new(ArgumentError)

  # Raised if no defaults are configured.
  ConfigurationError = Class.new(RuntimeError)

  # Create an encoder/decoder.
  #
  # Setup could be moderately expensive due to key derivation; you are recommended to cache
  # and reuse instances with equal parameters (e.g. setup the key generation once per runtime).
  #
  # * The stringified `prefix` is included in key derivation.  It may be nil or empty, in which
  #   case the separator is ignored and a bare param will be produced.
  #
  # * `config` is optional and intended for cases where you need finer control than global defaults.
  #
  # Mixing incompatible character encodings across prefix/separator/payload may raise
  # Encoding::CompatibilityError or Epithet::FormatError.  Don't expect UTF-16LE to work.
  #
  # The simplest typical invocation is `Epithet.new('prefix')`.
  #
  def initialize(prefix, config: Epithet.defaults)
    prefix = -String(prefix)
    @prefix = prefix.empty? ? prefix : -(prefix + config.separator)
    @wire_prefix = @prefix.b.freeze
    key_salt = [prefix.bytesize, prefix, config.context.bytesize, config.context].pack('Q>Z*Q>Z*')
    @codec = config.codec

    cipher_key_len = OpenSSL::Cipher.new(config.cipher).key_len
    digest_key_len = OpenSSL::Digest.new(config.digest).block_length
    cipher_key = config.keygen.generate("epithet:cipher:#{config.cipher}", key_salt, cipher_key_len)
    digest_key = config.keygen.generate("epithet:digest:#{config.digest}", key_salt, digest_key_len)

    @encryptor = OpenSSL::Cipher.new(config.cipher).encrypt.tap { |c| c.key = cipher_key; c.padding = 0 }
    @decryptor = OpenSSL::Cipher.new(config.cipher).decrypt.tap { |c| c.key = cipher_key; c.padding = 0 }
    @hmac = OpenSSL::HMAC.new(digest_key, config.digest)
  end

  # Encode a 64-bit unsigned integer to a prefixed base58 string.
  # Raises ArgumentError on invalid values.
  def encode(id)
    raise ArgumentError, 'not a 64-bit unsigned integer' unless Integer === id && id.bit_length <= 64 && id >= 0

    e = @encryptor.dup
    h = @hmac.dup
    pt = [id].pack('Q>')
    m = h.update(pt).digest
    block = e.update([pt, m].pack('a8a8')) + e.final
    ct = block.unpack('Q>2').then { (_1 << 64) + _2 }

    @prefix + @codec.i2s(ct)
  end

  # Decode a prefixed or raw base58 string to an integer.  The input is
  # stringified and read as bytes, whatever its encoding; raw inputs are
  # recognised by their exact payload length.
  #
  # Returns the integer on success, nil if authentication fails.
  # Raises FormatError on invalid wire format (see Block58#valid?).
  def decode(s)
    s = String(s).b
    s = s.delete_prefix(@wire_prefix) unless s.bytesize == @codec.size
    raise FormatError, 'unexpected format' unless @codec.valid?(s)

    d = @decryptor.dup
    h = @hmac.dup
    ct = @codec.s2i(s)
    block = d.update([ct >> 64, ct].pack('Q>2')) + d.final
    pt, m = block.unpack('a8a8')
    id = pt.unpack1('Q>')

    cteq([h.update(pt).digest].pack('a8'), m) ? id : nil
  end

  # Constant time octet-string comparison.
  def cteq(a, b) # :nodoc:
    return false unless a.bytesize == b.bytesize
    OpenSSL.fixed_length_secure_compare(a, b)
  end

  class << self
    # Configure the library.
    #
    # #### Examples
    #
    #     # As it might appear in an initializer
    #     Epithet.configure(
    #       passphrase: ENV.fetch('EPITHET_PASSPHRASE'),
    #       scrypt: { salt: "#{MyApp.name}/#{MyApp.env}" }
    #     )
    #
    #     # Retaining already-configured passphrase but updating context,
    #     # and using a custom separator.
    #     Epithet.configure(
    #       keygen: Epithet.defaults.keygen,
    #       context: 'rotation-19',
    #       separator: '-'
    #     )
    #
    # #### Options
    #
    # *   `:passphrase` - Install new key generator with scrypt-derived key material
    # *   `:scrypt` - Override scrypt parameters (cost, salt, provider etc); see Epithet::Scrypt
    # *   `:keygen` - Use an existing key generator
    # *   `:cipher` - Must be a 128-bit block cipher in ECB mode or equivalent; omit for standard `aes-256-ecb`
    # *   `:digest` - Must be >= 64 bits digest; omit for standard `sha256`
    # *   `:separator` - String inserted between the prefix and the generated param.
    #                    Omit for standard `_`.  May be `nil`.  Must not share bytes with the alphabet.
    #                    Not emitted when prefix is `nil` or empty.
    # *   `:alphabet` - Custom base58 alphabet for the wire encoding.  Must be strictly ascending bytes.
    # *   `:context` - If supplied, string form is included in subkey derivation.
    #                  Useful for purpose separation, or rotation epochs.
    #
    # At minimum, one of `passphrase:` or `keygen:` is required.
    #
    # If passing an existing key generator, the object must respond to `generate(info, salt, length)`
    # and return a byte string suitable for use with OpenSSL cryptographic primitives.
    # Configuration sharing means an alternative keygen must support concurrent `generate` calls.
    #
    # See [`SECURITY.md`](SECURITY.md) for discussion of ciphers & digests.
    #
    # #### Multiple configurations
    #
    # You can produce & store configurations, thus:
    #
    #     cfg = Epithet::Config.new(
    #       keygen: my_key_gen,
    #       cipher: 'camellia-256-ecb',
    #       digest: 'sha224'
    #     )
    #
    # and either install this as default with
    #
    #     Epithet.configure(cfg)
    #
    # or pass it to `Epithet::new` as
    #
    #     acct_epithet = Epithet.new('acct', config: cfg)
    #
    def configure(opts) = @defaults = Config === opts ? opts : Config.new(opts)
    def defaults() = @defaults || raise(ConfigurationError, 'no Epithet defaults configured')
  end
end
