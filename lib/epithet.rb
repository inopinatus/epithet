# frozen_string_literal: true

require 'epithet/version'
require 'openssl'

#
# Epithet, a tool for external identifiers.
#
# Given a 64-bit value such as a database sequence ID, and a context-specific
# prefix (typically a model or table name), produces a replayable string parameter of
# consistent length, with modest obfuscation and authentication properties.
#
# Pseudo-AEAD is via `AES-256-ECB(id(8B) + HMAC-SHA256(id)[0,7])` with the result
# base58 encoded for transmission and the contextual prefix prepended.
#
# Subkeys for AES and HMAC are by default derived with HKDF using an internal key
# generator that takes IKM from a passphrase via scrypt.  An alternative key generator
# may be injected via Config objects. Subkeys are salted by prefix and an optional
# additional salt, which may be useful for purpose separation or rotation.
#
# Example usage:
#
#     # in setup-environment.sh
#     EPITHET_PASSPHRASE='example only'
#
#     # ... later, in Ruby ...
#     Epithet.configure(passphrase: ENV.fetch('EPITHET_PASSPHRASE'))
#     user_epithet = Epithet.new('user')
#     user_epithet.encode(1) #=> "user_DAG6Joc5JmgygTBuEo8a9K"
#
class Epithet
  # Create an encoder/decoder.
  #
  # Setup could be moderately expensive due to key derivation; you are recommended to cache
  # and reuse instances with equal parameters (e.g. setup once per model)
  #
  # * `prefix` is stringified, and may be nil, producing an empty prefix.
  #   The prefix is included in the salt for key generation.
  #
  # * `config` is optional and intended for cases where you needed finer control than global defaults.
  #
  # The simplest typical invocation is `Epithet.new('prefix')`.
  #
  def initialize(prefix, config: Epithet.defaults)
    prefix = String(prefix)
    key_salt = [prefix.bytesize, prefix, config.salt.bytesize, config.salt].pack("Q>Z*Q>Z*")
    @block58 = Block58.new(16)
    @prefix_s = "#{prefix}#{config.separator}"

    cipher_key_len = OpenSSL::Cipher.new(config.cipher).key_len
    digest_key_len = OpenSSL::Digest.new(config.digest).block_length
    cipher_key = config.keygen.generate("epithet:ecb", key_salt, cipher_key_len)
    digest_key = config.keygen.generate("epithet:mac", key_salt, digest_key_len)

    @encryptor = OpenSSL::Cipher.new(config.cipher).encrypt.tap { |c| c.key = cipher_key; c.padding = 0 }
    @decryptor = OpenSSL::Cipher.new(config.cipher).decrypt.tap { |c| c.key = cipher_key; c.padding = 0 }
    @hmac = OpenSSL::HMAC.new(digest_key, config.digest)
  end

  # Encode a 64-bit unsigned Integer to a prefixed Base58 string.
  # Raises ArgumentError on invalid values.
  def encode(id)
    raise ArgumentError, "not a 64-bit unsigned integer" unless Integer === id && id.size == 8 && id >= 0

    e = @encryptor.dup
    h = @hmac.dup
    pt = [id].pack('Q>')
    m = h.update(pt).digest
    block = e.update([pt, m].pack('a8a8')) + e.final
    ct = block.unpack('Q>2').then { (_1 << 64) + _2 }

    @prefix_s + @block58.i2s(ct)
  end

  # Decode a prefixed or raw Base58 string to an Integer.
  #
  # Returns the Integer on success, nil if authentication fails.
  # Raises ArgumentError on invalid formats.
  def decode(s)
    s = s.delete_prefix(@prefix_s)
    raise ArgumentError, "unexpected format" unless @block58.valid?(s)

    d = @decryptor.dup
    h = @hmac.dup
    ct = @block58.s2i(s)
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
    #     Epithet.configure(passphrase: ENV.fetch('EPITHET_PASSPHRASE'))
    #
    #     # Retaining already-configured passphrase but updating salt,
    #     # and using a custom separator.
    #     Epithet.configure(
    #       keygen: Epithet.defaults.keygen,
    #       salt: 'rotation-19',
    #       separator: '-'
    #     )
    #
    # #### Options
    #
    # *   `:passphrase` - Install new key generator with scrypt-derived key material
    # *   `:scrypt` - Params for scrypt; omit to use `Keygen::DEFAULT_SCRYPT_PARAMS`
    # *   `:keygen` - Install an existing key generator
    # *   `:cipher` - Must be a 128-bit block cipher in ECB mode or equivalent; omit for standard `aes-256-ecb`
    # *   `:digest` - Must be >= 64 bits; omit for standard `sha256`
    # *   `:separator` - Inserted as string between the prefix and the generated param. may be nil; omit for underscore.
    # *   `:salt` - If supplied, stringified form is included in subkey derivation
    #
    # At minimum, one of `passphrase:` or `keygen:` is required.
    # Configuration via `passphrase` is recommended.
    # If passing an existing key generator, the object must respond to `#generate(info, salt, length)`.
    #
    # #### Cryptographic choices
    #
    # The default cipher & digest are conservatively chosen as `aes-256-ecb` and `sha256`.
    # A cryptologic discussion of alternatives is outside the scope of this documentation.
    #
    # Streaming ciphers (e.g. chacha20) or block ciphers in streaming modes (e.g. aes-256-ctr)
    # must not be used, since no nonce/IV value is included in the output message, making them
    # trivially vulnerable to known-plaintext attacks in this usage.
    #
    # This library is intended for high-performance obfuscation of sequences, deflection of
    # casual tampering, and conversion to a compact, stable wire parameter format.  Although
    # it uses standard cryptographic primitives to do so, the design trade-off of the compact
    # format means it is not intended to defeat nation-state security services, talented
    # cryptographers, or even a well-resourced enterprise.  Use at your own risk.
    #
    # Cipher modes requiring a nonce or IV may be rejected at configuration time, to prevent
    # inadvertent misconfiguration.
    #
    # #### Multiple configurations
    #
    # You can produce & store configurations, thus:
    #
    #     cfg = Epithet::Config.new(keygen: my_key_gen, cipher: 'stronk-512-jcb', digest: 'md7')
    #
    # and either install this as default with
    #
    #     Epithet.configure(cfg)
    #
    # or pass it in to `Epithet::new` as
    #
    #     acct_epithet = Epithet.new('acct', config: cfg)
    #
    def configure(opts) = @defaults = Config === opts ? opts : Config.new(opts)
    def defaults() = @defaults || raise(RuntimeError, "no Epithet defaults configured")
  end

  # Class for passing around preset configs. See Epithet::configure for options.
  class Config
    attr_reader :keygen, :salt, :separator, :cipher, :digest # :nodoc:
    def initialize(opts = {})
      opts = opts.dup
      @separator = String(opts.delete(:separator) { '_' })
      @salt = String(opts.delete(:salt))
      @cipher = opts.delete(:cipher) || 'aes-256-ecb'
      @digest = opts.delete(:digest) || 'sha256'

      cipher = OpenSSL::Cipher.new(@cipher)
      raise ArgumentError, "#{@cipher} not a 128-bit block cipher" if cipher.block_size != 16
      raise ArgumentError, "#{@cipher} requires an IV/nonce" if cipher.iv_len != 0
      raise ArgumentError, "#{@digest} produces < 64-bit digest" if OpenSSL::Digest.new(@digest).digest_length < 8

      @keygen = opts.delete(:keygen) || Keygen.new(
        passphrase: opts.delete(:passphrase),
        digest: @digest,
        scrypt: opts.delete(:scrypt) || Keygen::DEFAULT_SCRYPT_PARAMS)
      raise ArgumentError, "unused option(s) #{opts.keys}" unless opts.empty?
    end
  end

  # Key derivation helper
  class Keygen
    # Default parameters for scrypt.
    DEFAULT_SCRYPT_PARAMS = {
      salt: 'epithet-default',
      N: 1<<17,
      r: 8,
      p: 1,
      length: 32
    }.freeze

    # Create a new key generator from either high-entropy key material, or a supplied passphrase.
    def initialize(ikm: nil, passphrase: nil, digest: "sha256", scrypt: DEFAULT_SCRYPT_PARAMS)
      if (passphrase.nil? && ikm.nil?) || (!passphrase.nil? && !ikm.nil?)
        raise ArgumentError, "keygen requires either ikm or passphrase"
      end

      @ikm = ikm || OpenSSL::KDF.scrypt(passphrase, **scrypt)
      @digest = digest
    end

    def inspect
      "#<#{self.class}:#{'%#016x' % (object_id << 1)} digest=#{@digest}>"
    end

    # Derive a key via HKDF.
    def generate(info, salt, length)
      OpenSSL::KDF.hkdf(@ikm, hash: @digest, info: info, salt: salt, length: length)
    end
  end

  # Fixed-length Base58 codec for a fixed-size block.
  class Block58
    Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    # Create a codec for a block size in bytes.
    def initialize(block_size, alphabet: Alphabet)
      @alphabet = alphabet.b.freeze
      raise ArgumentError, "invalid alphabet length" unless @alphabet.bytesize == 58
      @size = ((block_size * 8) / Math.log2(58)).ceil(0)
      @charsel = @alphabet.gsub(/[\^\-\\]/, '\\\\\&').freeze
      @blank = @alphabet[0] * @size
      @lut = @alphabet.each_byte.with_index.with_object("\0" * 256) { |(val, idx), lut| lut.setbyte(val, idx) }.freeze
    end

    def inspect
      "#<#{self.class}:#{'%#016x' % (object_id << 1)} size=#{@size} alphabet=#{@alphabet}>"
    end

    # Return true if the string has the right size and alphabet.
    def valid?(s)
      String === s && s.bytesize == @size && s.count(@charsel) == @size
    end

    # Encode a non-negative Integer to fixed-length Base58.
    # Using divmod+setbyte is faster than Integer#digits under YJIT, and about equal without.
    def i2s(int)
      alphabet = @alphabet
      out = @blank.dup
      idx = @size - 1
      n = int
      while idx >= 0 && n > 0
        n, rem = n.divmod(58)
        out.setbyte(idx, alphabet.getbyte(rem))
        idx -= 1
      end
      out
    end

    # Decode a fixed-length Base58 string to an Integer.
    # Assumes the input passes `#valid?`.
    def s2i(str)
      # By unrolling coefficients, this is ~8x faster than Horner's scheme
      #
      #   str.each_byte.inject(0) { _1 * 58 + @lut[_2] }
      #
      # at computing the inner product when using YJIT, by chunking
      # intermediate results into 64-bit integers.
      lut = @lut

      acc0 = lut.getbyte(str.getbyte(0)) * 7427658739644928 +
             lut.getbyte(str.getbyte(1)) * 128063081718016 +
             lut.getbyte(str.getbyte(2)) * 2207984167552 +
             lut.getbyte(str.getbyte(3)) * 38068692544 +
             lut.getbyte(str.getbyte(4)) * 656356768 +
             lut.getbyte(str.getbyte(5)) * 11316496 +
             lut.getbyte(str.getbyte(6)) * 195112 +
             lut.getbyte(str.getbyte(7)) * 3364 +
             lut.getbyte(str.getbyte(8)) * 58 +
             lut.getbyte(str.getbyte(9))

      acc1 = lut.getbyte(str.getbyte(10)) * 7427658739644928 +
             lut.getbyte(str.getbyte(11)) * 128063081718016 +
             lut.getbyte(str.getbyte(12)) * 2207984167552 +
             lut.getbyte(str.getbyte(13)) * 38068692544 +
             lut.getbyte(str.getbyte(14)) * 656356768 +
             lut.getbyte(str.getbyte(15)) * 11316496 +
             lut.getbyte(str.getbyte(16)) * 195112 +
             lut.getbyte(str.getbyte(17)) * 3364 +
             lut.getbyte(str.getbyte(18)) * 58 +
             lut.getbyte(str.getbyte(19))

                               lut.getbyte(str.getbyte(21)) +
                          58 * lut.getbyte(str.getbyte(20)) +
                        3364 * acc1 +
      1449225352009601191936 * acc0
    end
  end
end
