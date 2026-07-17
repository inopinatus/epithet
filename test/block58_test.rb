# frozen_string_literal: true

require_relative 'test_helper'

class Block58Test < Minitest::Test
  VECTORS = {
    0 => '1111111111111111111111',
    1 => '1111111111111111111112',
    57 => '111111111111111111111z',
    58 => '1111111111111111111121',
    59 => '1111111111111111111122',
    (58**2) => '1111111111111111111211',
    (58**2) - 1 => '11111111111111111111zz',
    (58**10) => '1111111111121111111111',
    (1 << 64) => '11111111111jpXCZedGfVR',
    (1 << 127) => 'GokLUsho3eiVvNYNd1wgfy',
    (1 << 128) - 1 => 'YcVfxkQb6JRzqk5kF2tNLv',
  }.freeze

  def setup
    @block = Epithet::Block58.new(16)
  end

  def test_i2s_vectors
    VECTORS.each do |value, encoded|
      assert_equal encoded, @block.i2s(value)
      assert @block.valid?(encoded)
    end
  end

  def test_s2i_vectors
    VECTORS.each do |value, encoded|
      assert_equal value, @block.s2i(encoded)
    end
  end

  def test_fast_vectors
    fast = Epithet::Block58.build(16)

    VECTORS.each do |value, encoded|
      assert_equal encoded, fast.i2s(value)
      assert_equal value, fast.s2i(encoded)
    end
  end

  def test_round_trip
    VECTORS.each do |value, encoded|
      assert_equal value, @block.s2i(@block.i2s(value))
      assert_equal encoded, @block.i2s(@block.s2i(encoded))
    end
  end

  def test_reject_invalid
    good = @block.i2s(0)

    refute @block.valid?(good[0...-1])
    refute @block.valid?(good + '1')
    refute @block.valid?(good.sub('1', '0'))

    assert @block.valid?('YcVfxkQb6JRzqk5kF2tNLv') # (1 << 128) - 1
    refute @block.valid?('YcVfxkQb6JRzqk5kF2tNLw') # (1 << 128)
    refute @block.valid?('z' * 22)
  end

  def test_i2s_rejects_out_of_domain_input
    [-1, 1 << 128, 58**22, '1', 4.2, nil].each do |bad|
      assert_raises(ArgumentError) { @block.i2s(bad) }
    end
  end

  # We neither support or produce UTF-16LE, it's an ASCII-incompatible hazard.
  def test_valid_reads_bytes_whatever_the_encoding
    assert @block.valid?('1111111111111111111112'.encode('US-ASCII'))
    refute @block.valid?(('A' * 11).encode('UTF-16LE'))
    refute @block.valid?(('1' + ("\xFF" * 21)).force_encoding('UTF-8'))
  end

  def test_alphabet_must_be_strictly_ascending
    assert_raises(ArgumentError) { Epithet::Block58.new(16, alphabet: Epithet::Block58::Alphabet.reverse) }
    assert_raises(ArgumentError) { Epithet::Block58.new(16, alphabet: Epithet::Block58::Alphabet.sub('2', '1')) }
  end

  def test_build_variant_selection
    assert_instance_of Epithet::Block58::Unrolled16, Epithet::Block58.build(16)
    assert_instance_of Epithet::Block58, Epithet::Block58.build(8)
    assert_instance_of Epithet::Block58, Epithet::Block58.build(32)
  end

  def test_unrolled_blocksize_restricted
    assert_raises(ArgumentError) { Epithet::Block58::Unrolled16.new(8) }
    assert_raises(ArgumentError) { Epithet::Block58::Unrolled16.new(32) }
  end

  def test_unrolled_agrees_with_generic
    generic = Epithet::Block58.new(16)
    unrolled = Epithet::Block58.build(16)
    rng = Random.new(58)

    1000.times do
      value = rng.rand(1 << 128)
      encoded = generic.i2s(value)

      assert_equal encoded, unrolled.i2s(value)
      assert_equal value, unrolled.s2i(encoded)
    end
  end

  def test_build_round_trips_other_block_sizes
    rng = Random.new(58)

    [1, 4, 8, 17, 32, 64].each do |block_size|
      block = Epithet::Block58.build(block_size)
      max = (1 << (block_size * 8)) - 1

      [0, 1, max, rng.rand(max), rng.rand(max)].each do |value|
        assert_equal value, block.s2i(block.i2s(value)), "block_size=#{block_size} value=#{value}"
      end
      assert block.valid?(block.i2s(max))
      refute block.valid?(block.i2s(max).succ)
      assert_raises(ArgumentError) { block.i2s(max + 1) }
    end
  end
end
