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
  # Mixed character encodings across prefix & separator may raise Encoding::CompatibilityError.
  #
  # The simplest typical invocation is `Epithet.new('prefix')`.
  #
  def initialize(prefix, config: Epithet.defaults)
    prefix = String(prefix)
    @prefix = prefix.empty? ? prefix : prefix + config.separator
    @wire_prefix = @prefix.b
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
    # *   `:scrypt` - Merge params for scrypt
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
    #
    # See [`SECURITY.md`](SECURITY.md) for discussion of ciphers & digests.
    #
    # #### Multiple configurations
    #
    # You can produce & store configurations, thus:
    #
    #     cfg = Epithet::Config.new(
    #       keygen: my_key_gen,
    #       cipher: 'stronk-512-jcb',
    #       digest: 'md7'
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
    def defaults() = @defaults || raise('no Epithet defaults configured')
  end

  # Class for passing around preset configs. See Epithet::configure for options.
  class Config
    attr_reader :keygen, :context, :separator, :cipher, :digest, :codec # :nodoc:

    def initialize(opts = {})
      opts = opts.dup
      @separator = -String(opts.delete(:separator) { '_' })
      @context = -String(opts.delete(:context))
      alphabet = String(opts.delete(:alphabet) { Block58::Alphabet })
      @cipher = -(opts.delete(:cipher) || 'aes-256-ecb').downcase
      @digest = -(opts.delete(:digest) || 'sha256').downcase
      keygen, passphrase, scrypt = %i[keygen passphrase scrypt].map { opts.delete it }

      cipher = OpenSSL::Cipher.new(@cipher)
      raise ArgumentError, 'separator intersects alphabet' if @separator.bytes.intersect?(alphabet.bytes)
      raise ArgumentError, "#{@cipher} not a 128-bit block cipher" if cipher.block_size != 16
      raise ArgumentError, "#{@cipher} requires an IV/nonce" if cipher.iv_len != 0
      raise ArgumentError, "#{@digest} produces < 64-bit digest" if OpenSSL::Digest.new(@digest).digest_length < 8
      raise ArgumentError, 'use keygen: or passphrase:, not both' if keygen && (passphrase || scrypt)
      raise ArgumentError, 'one of passphrase: or keygen: is required' unless keygen || passphrase
      raise ArgumentError, "unused option(s) #{opts.keys}" unless opts.empty?

      @codec = Block58.build(cipher.block_size, alphabet:)
      @keygen = keygen || Keygen.new(passphrase:, digest: @digest, scrypt:)
      freeze
    end
  end

  # Key derivation helper
  class Keygen
    # Default parameters for scrypt.
    #
    # ```ruby
    # DEFAULT_SCRYPT_PARAMS = {
    #   salt: 'epithet-default',
    #   N: 1 << 17,
    #   r: 8,
    #   p: 1
    # }.freeze
    # ```
    DEFAULT_SCRYPT_PARAMS = {
      salt: 'epithet-default',
      N: 1 << 17,
      r: 8,
      p: 1
    }.freeze

    # Create a new key generator from either high-entropy key material, or a supplied passphrase.
    # Supplied scrypt params, if any, are merged over DEFAULT_SCRYPT_PARAMS.
    def initialize(ikm: nil, passphrase: nil, digest: 'sha256', scrypt: {})
      if (passphrase.nil? && ikm.nil?) || (!passphrase.nil? && !ikm.nil?)
        raise ArgumentError, 'keygen requires either ikm or passphrase'
      end
      raise ArgumentError, 'scrypt length is not configurable' if scrypt&.key?(:length)

      @ikm = (ikm&.b || OpenSSL::KDF.scrypt(passphrase, **DEFAULT_SCRYPT_PARAMS, **scrypt, length: 32)).freeze
      @digest = -String(digest)
      freeze
    end

    def inspect
      "#<#{self.class}:#{'%#016x' % (object_id << 1)} digest=#{@digest}>"
    end

    # Derive a key via HKDF.
    def generate(info, salt, length)
      OpenSSL::KDF.hkdf(@ikm, hash: @digest, info:, salt:, length:)
    end
  end

  # Fixed-length base58 codec for a fixed-size block.
  #
  # Obtain codecs via Block58::build, which selects the fastest variant for
  # the block size, an unrolled decoder for 16-byte blocks, or the generic
  # chunked decoder otherwise.
  class Block58
    # `= '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'`
    Alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

    POW58 = Array.new(11) { 58**it }.freeze # :nodoc:

    attr_reader :size

    # Same as ::new but may select a tuned subclass for performance.
    def self.build(block_size, ...) = (block_size == 16 ? Unrolled16 : self).new(block_size, ...)

    # Create a codec for a block size in bytes.
    #
    # The alphabet must be 58 distinct bytes in ascending order, so that
    # lexicographic order agrees with numeric order.
    def initialize(block_size, alphabet: Alphabet)
      raise ArgumentError, 'invalid block size' unless Integer === block_size && block_size > 0
      @alphabet = alphabet.b.freeze
      raise ArgumentError, 'invalid alphabet length' unless @alphabet.bytesize == 58
      raise ArgumentError, 'alphabet not strictly ascending' unless @alphabet.bytes.each_cons(2).all? { _2 > _1 }
      @size = ((block_size * 8) / Math.log2(58)).ceil
      @charsel = @alphabet.gsub(/[\^\-\\]/, '\\\\\&').freeze
      @blank = @alphabet[0] * @size
      @lut = @alphabet.each_byte.with_index.with_object("\0" * 256) { |(val, idx), lut| lut.setbyte(val, idx) }.freeze
      @limit = 1 << (block_size * 8)
      @max = i2s(@limit - 1).freeze
    end

    def inspect
      "#<#{self.class}:#{'%#016x' % (object_id << 1)} size=#{@size} alphabet=#{@alphabet}>"
    end

    # Return true if the string is in range with the right size and alphabet.
    # The input is read as bytes, whatever its encoding.
    def valid?(s)
      String === s && s.bytesize == @size && (s = s.b) <= @max && s.count(@charsel) == @size
    end

    # Encode an acceptable integer to fixed-length base58.
    def i2s(int)
      raise ArgumentError, 'integer out of block range' unless Integer === int && int >= 0 && int < @limit

      # Using divmod+setbyte is faster than Integer#digits under YJIT,
      # and about equal in plain MRI.
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

    # Decode a fixed-length base58 string to an integer.
    # Assumes the input passes `#valid?`, behaviour undefined if it doesn't.
    def s2i(str)
      # Chunking intermediate results into 64-bit integers is ~5x faster
      # under YJIT than Horner's scheme
      #
      #   str.each_byte.inject(0) { _1 * 58 + @lut[_2] }
      #
      # at computing the inner product.
      lut = @lut
      size = @size
      pow = POW58
      acc = 0
      pos = 0
      while pos < size
        n = size - pos
        n = 10 if n > 10
        chunk = 0
        i = 0
        while i < n
          chunk = (chunk * 58) + lut.getbyte(str.getbyte(pos))
          pos += 1
          i += 1
        end
        acc = (acc * pow[n]) + chunk
      end
      acc
    end

    # Specialised decoder for 16-byte blocks (22 digits) with a fully unrolled inner product.
    class Unrolled16 < Block58
      def initialize(...)
        super
        raise ArgumentError, 'unrolled codec requires a 16-byte block' unless @size == 22
      end

      # Decode a 22-digit base58 string to an integer.
      # Assumes the input passes `#valid?`, behaviour undefined if it doesn't.
      def s2i(str)
        # rubocop:disable Style/NumericLiterals, Lint/AmbiguousOperatorPrecedence, Layout
        #
        # By unrolling the chunks against literal coefficients, this tested with Ruby 4.0
        # at ~1.5x faster under YJIT than the generic chunked Block58#s2i, and ~6x faster
        # than Horner's scheme.
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
               lut.getbyte(str.getbyte(20)) * 58 +
                                       acc1 * 3364 +
                                       acc0 * 1449225352009601191936

        # rubocop:enable Style/NumericLiterals, Lint/AmbiguousOperatorPrecedence, Layout
      end
    end
  end
end
