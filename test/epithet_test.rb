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

  def test_decode_rejects_out_of_range_alias
    epithet = Epithet.new('user')
    block58 = Epithet::Block58.new(16)
    canonical = epithet.encode(42).delete_prefix('user_')
    aliased = block58.i2s(block58.s2i(canonical) + (1 << 128))

    refute_equal canonical, aliased
    assert_raises(ArgumentError) { epithet.decode('user_' + aliased) }
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

  def test_separator_must_not_intersect_alphabet
    error = assert_raises(ArgumentError) { Epithet::Config.new(keygen: Cfg.keygen, separator: 'z') }

    assert_match(/separator/, error.message)
    assert_raises(ArgumentError) do
      Epithet::Config.new(keygen: Cfg.keygen, alphabet: [*'0'..'4', *'A'..'Z', '_', *'a'..'z'].join)
    end
  end

  def test_custom_alphabet
    alphabet = [*'0'..'5', *'A'..'Z', *'a'..'z'].join
    cfg = Epithet::Config.new(keygen: Cfg.keygen, alphabet: alphabet)
    epithet = Epithet.new('user', config: cfg)
    param = epithet.encode(42)

    assert_equal 42, epithet.decode(param)
    assert_equal Epithet.new('user').encode(42), 'user_' + param.delete_prefix('user_').tr(alphabet, Epithet::Block58::Alphabet)
  end

  def test_prefix_mismatch
    user = Epithet.new('user')
    acct = Epithet.new('acct')
    payload = user.encode(42).delete_prefix('user_')

    assert_equal 42, user.decode(payload)
    assert_nil acct.decode(payload)
  end

  def test_raw_decode_raw_with_empty_separator
    cfg = Epithet::Config.new(keygen: Cfg.keygen, separator: nil)
    epithet = Epithet.new('1', config: cfg)
    id = (0..).find { |i| epithet.encode(i).start_with?('11') }
    param = epithet.encode(id)

    assert_equal id, epithet.decode(param)
    assert_equal id, epithet.decode(param.delete_prefix('1'))
  end
end
