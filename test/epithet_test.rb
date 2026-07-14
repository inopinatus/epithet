# frozen_string_literal: true

require_relative 'test_helper'

class EpithetTest < Minitest::Test
  def test_round_trip
    epithet = Epithet.new('user')
    id = 123_456_789
    param = epithet.encode(id)

    assert_equal id, epithet.decode(param)
  end

  def test_decode_returns_nil_on_auth_failure
    epithet = Epithet.new('user')
    param = epithet.encode(42)

    base = param.delete_prefix('user_')
    alphabet = Epithet::Block58::Alphabet
    idx = alphabet.index(base[-1])
    alt = alphabet[(idx + 1) % alphabet.length]
    tampered = 'user_' + base[0...-1] + alt

    assert_nil epithet.decode(tampered)
  end

  def test_decode_raise_on_invalid_format
    epithet = Epithet.new('user')

    assert_raises(ArgumentError) { epithet.decode('user_123') }
  end

  def test_decode_allows_omitted_prefix
    epithet = Epithet.new('user')
    id = 99
    param = epithet.encode(id)
    base = param.delete_prefix('user_')

    assert_equal id, epithet.decode(base)
  end

  def test_encode_rejects_invalid_id
    epithet = Epithet.new('user')

    assert_raises(ArgumentError) { epithet.encode(-1) }
    assert_raises(ArgumentError) { epithet.encode(1 << 64) }
    assert_raises(ArgumentError) { epithet.encode(nil) }
    assert_raises(ArgumentError) { epithet.encode('1') }
  end

  def test_keygen_mismatch
    epithet = Epithet.new('user')
    param = epithet.encode(42)

    wrong_keygen = Epithet::Config.new(keygen: Epithet::Keygen.new(ikm: 'different-test-key'.b))
    wrong = Epithet.new('user', config: wrong_keygen)

    assert_nil wrong.decode(param)
  end
end
