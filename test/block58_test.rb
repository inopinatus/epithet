require_relative "test_helper"

class Block58Test < Minitest::Test
  VECTORS = {
    0 => "1111111111111111111111",
    1 => "1111111111111111111112",
    57 => "111111111111111111111z",
    58 => "1111111111111111111121",
    59 => "1111111111111111111122",
    58**2 - 1 => "11111111111111111111zz",
    58**2 => "1111111111111111111211",
    58**10 => "1111111111121111111111",
    2**64 => "11111111111jpXCZedGfVR",
    2**127 => "GokLUsho3eiVvNYNd1wgfy",
    (1 << 128) - 1 => "YcVfxkQb6JRzqk5kF2tNLv",
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

  def test_round_trip
    VECTORS.each do |value, encoded|
      assert_equal value, @block.s2i(@block.i2s(value))
      assert_equal encoded, @block.i2s(@block.s2i(encoded))
    end
  end

  def test_valid_rejects_wrong_length_or_charset
    good = @block.i2s(0)

    refute @block.valid?(good[0...-1])
    refute @block.valid?(good + "1")
    refute @block.valid?(good.sub("1", "0"))
  end
end
