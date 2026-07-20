# frozen_string_literal: true

class Epithet
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
      @blank = (@alphabet[0] * @size).freeze
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
