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

  def test_decode_stringifies_junk_and_raises_format_error
    epithet = Epithet.new('user')

    [nil, 42, 4.2, [], {}, :junk].each do |junk|
      assert_raises(Epithet::FormatError) { epithet.decode(junk) }
    end
  end

  def test_decode_rejects_incompatible_encodings
    epithet = Epithet.new('user')
    param = epithet.encode(42)

    assert_raises(Epithet::FormatError) { epithet.decode(param.encode('UTF-16LE')) }
    assert_raises(Epithet::FormatError) { epithet.decode('elevenchars'.encode('UTF-16LE')) }
  end

  def test_decode_accepts_a_to_str_duck
    epithet = Epithet.new('user')
    duck = Struct.new(:s) { def to_str = s }

    assert_equal 42, epithet.decode(duck.new(epithet.encode(42)))
  end

  def test_decode_wrong_prefix_raises_format_error
    param = Epithet.new('user').encode(42)

    assert_raises(Epithet::FormatError) { Epithet.new('acct').decode(param) }
  end

  def test_format_error_is_an_argument_error
    assert_operator Epithet::FormatError, :<, ArgumentError
  end

  def test_decode_rejects_out_of_range_alias
    epithet = Epithet.new('user')
    block58 = Epithet::Block58.new(16)

    # An in-range alias only exists for ciphertexts below 58**22 - 2**128,
    # hunt for an id whose ciphertext leaves headroom.
    threshold = (58**22) - (1 << 128)
    id = (0..).find { |i| block58.s2i(epithet.encode(i).delete_prefix('user_')) < threshold }
    canonical = epithet.encode(id).delete_prefix('user_')
    alphabet = Epithet::Block58::Alphabet
    aliased = (block58.s2i(canonical) + (1 << 128)).digits(58).reverse.map { alphabet[it] }.join.rjust(22, alphabet[0])

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

  def test_nil_and_empty_prefixes_produce_bare_param
    bare = Epithet.new(nil)
    empty = Epithet.new('')
    param = bare.encode(7)

    assert_equal 22, param.bytesize
    assert_equal param, empty.encode(7)
    assert_equal 7, bare.decode(param)
    assert_equal 7, empty.decode(param)
  end

  def test_config_rejects_invalid_alphabet
    assert_raises(ArgumentError) { Epithet::Config.new(keygen: Cfg.keygen, alphabet: 'abc') }
    assert_raises(ArgumentError) { Epithet::Config.new(keygen: Cfg.keygen, alphabet: Epithet::Block58::Alphabet.reverse) }
  end

  def test_config_rejects_unsupported_cipher_modes
    error = assert_raises(ArgumentError) { Epithet::Config.new(keygen: Cfg.keygen, cipher: 'aes-256-cbc') }

    assert_match(/IV/, error.message)
    assert_raises(ArgumentError) { Epithet::Config.new(keygen: Cfg.keygen, cipher: 'aes-256-gcm') }
    assert_raises(ArgumentError) { Epithet::Config.new(keygen: Cfg.keygen, cipher: 'des-ede3') }
  end

  def test_config_rejects_unknown_algorithms
    cipher_error = assert_raises(ArgumentError) { Epithet::Config.new(keygen: Cfg.keygen, cipher: 'stronk-512-jcb') }
    digest_error = assert_raises(ArgumentError) { Epithet::Config.new(keygen: Cfg.keygen, digest: 'md7') }

    assert_match(/unknown cipher stronk-512-jcb/, cipher_error.message)
    assert_match(/unknown digest md7/, digest_error.message)
  end

  def test_config_rejects_keygen_alongside_passphrase_options
    assert_raises(ArgumentError) { Epithet::Config.new(keygen: Cfg.keygen, passphrase: 'pw') }
    assert_raises(ArgumentError) { Epithet::Config.new(keygen: Cfg.keygen, scrypt: { salt: 's' }) }
  end

  def test_keygen_requires_exactly_one_key_source
    assert_raises(ArgumentError) { Epithet::Keygen.new }
    assert_raises(ArgumentError) { Epithet::Keygen.new(ikm: 'k', passphrase: 'pw') }
  end

  def test_raw_decode_raw_with_empty_separator
    cfg = Epithet::Config.new(keygen: Cfg.keygen, separator: nil)
    epithet = Epithet.new('1', config: cfg)
    id = (0..).find { |i| epithet.encode(i).start_with?('11') }
    param = epithet.encode(id)

    assert_equal id, epithet.decode(param)
    assert_equal id, epithet.decode(param.delete_prefix('1'))
  end

  def test_encode_emits_prefix_compatible_encoding
    assert_equal Encoding::UTF_8, Epithet.new('user').encode(1).encoding
    assert_predicate Epithet.new(nil).encode(1), :ascii_only?
    assert_predicate Epithet.new('').encode(1), :ascii_only?
  end

  def test_encode_multibyte_prefix_yields_valid_utf8
    epithet = Epithet.new('café')
    param = epithet.encode(1)

    assert_equal Encoding::UTF_8, param.encoding
    assert_predicate param, :valid_encoding?
    assert param.start_with?('café_')
    assert_equal 1, epithet.decode(param)
  end

  def test_encode_falls_back_to_binary_for_unrepresentable_prefixes
    epithet = Epithet.new("caf\xE9".b)
    param = epithet.encode(1)

    assert_equal Encoding::BINARY, param.encoding
    assert_equal 1, epithet.decode(param)
  end

  def test_incompatible_prefix_and_separator_raise
    cfg = Epithet::Config.new(keygen: Cfg.keygen, separator: '·'.encode('UTF-16LE'))
    assert_raises(Encoding::CompatibilityError) { Epithet.new('user', config: cfg) }
  end

  def test_non_ascii_separator_yields_valid_utf8
    cfg = Epithet::Config.new(keygen: Cfg.keygen, separator: '·')
    epithet = Epithet.new('user', config: cfg)
    param = epithet.encode(42)

    assert_equal Encoding::UTF_8, param.encoding
    assert_predicate param, :valid_encoding?
    assert param.start_with?('user·')
    assert_equal 42, epithet.decode(param)
  end

  def test_multibyte_separator_round_trips
    cfg = Epithet::Config.new(keygen: Cfg.keygen, separator: '--')
    epithet = Epithet.new('user', config: cfg)
    param = epithet.encode(42)

    assert param.start_with?('user--')
    assert_equal 42, epithet.decode(param)
    assert_equal 42, epithet.decode(param.delete_prefix('user--'))
    assert_equal Epithet.new('user').encode(42).delete_prefix('user_'), param.delete_prefix('user--')
  end

  def test_scrypt_params_merge_and_season_the_keys
    salted = lambda do |salt|
      Epithet.new('user', config: Epithet::Config.new(passphrase: 'pw', scrypt: { N: 1 << 4, salt: }))
    end
    a = salted['app-a']
    b = salted['app-b']

    refute_equal a.encode(42), b.encode(42)
    assert_nil b.decode(a.encode(42))
    assert_equal a.encode(42), salted['app-a'].encode(42)
  end

  def test_scrypt_length_is_invariant
    assert_raises(ArgumentError) { Epithet::Config.new(passphrase: 'pw', scrypt: { length: 0 }) }
    assert_raises(ArgumentError) { Epithet::Keygen.new(passphrase: 'pw', scrypt: { length: 64 }) }
  end

  def test_config_requires_a_key_source
    error = assert_raises(ArgumentError) { Epithet::Config.new }

    assert_match(/passphrase/, error.message)
    assert_raises(ArgumentError) { Epithet::Config.new(scrypt: { salt: 'lonely' }) }
  end

  def test_configure_accepts_an_options_hash
    saved = Epithet.defaults
    Epithet.configure(passphrase: 'testing', scrypt: { N: 1 << 4 })

    assert_instance_of Epithet::Config, Epithet.defaults
    assert_equal 42, Epithet.new('user').decode(Epithet.new('user').encode(42))
  ensure
    Epithet.configure(saved)
  end

  def test_keygen_inspect_conceals_key_material
    keygen = Epithet::Keygen.new(ikm: 'super-secret-ikm')

    assert_match(/digest=sha256/, keygen.inspect)
    refute_match(/super-secret/, keygen.inspect)
  end

  def test_config_and_keygen_freeze_on_creation
    assert_predicate Cfg, :frozen?
    assert_predicate Cfg.keygen, :frozen?
  end

  def test_defaults_raise_configuration_error_when_unconfigured
    saved = Epithet.defaults
    Epithet.instance_variable_set(:@defaults, nil)

    assert_raises(Epithet::ConfigurationError) { Epithet.defaults }
  ensure
    Epithet.configure(saved)
  end
end
