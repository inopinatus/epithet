# frozen_string_literal: true

require_relative 'test_helper'

begin
  require 'scrypt'
rescue LoadError
  # will be skipped on this platform
end

# Scrypt provider selection
class ScryptTest < Minitest::Test
  CHEAP = { salt: 'scrypt-test', N: 16, r: 2, p: 1, length: 32 }.freeze

  def test_gem_scrypt_produces_identical_ikm_to_openssl_kdf
    skip 'no OpenSSL::KDF.scrypt on this platform' unless OpenSSL::KDF.respond_to?(:scrypt)
    skip 'scrypt gem not bundled' unless defined?(::SCrypt::Engine)

    provider_osl = Epithet::Scrypt::OpenSSL.new(**CHEAP)
    provider_gem = Epithet::Scrypt::SCryptGem.new(**CHEAP)
    assert_equal provider_osl.ikm('sekrit'), provider_gem.ikm('sekrit')
  end

  def test_automatic_scrypt_provider_steps_down_to_the_gem
    skip 'Ruby::Box is not enabled' unless defined?(Ruby::Box) && Ruby::Box.enabled?
    skip 'scrypt gem not bundled' unless defined?(::SCrypt::Engine)

    box = Ruby::Box.new
    box.load_path.replace($LOAD_PATH)
    box.require('openssl')
    box.eval('OpenSSL::KDF.singleton_class.undef_method(:scrypt) if OpenSSL::KDF.respond_to?(:scrypt)')
    box.require('scrypt')
    box.require('epithet')

    assert_same box::Epithet::Scrypt::SCryptGem, box::Epithet::Scrypt.auto
  end

  def test_explicit_provider_parameter_matches_preferred_automatic_selection
    skip 'no OpenSSL::KDF.scrypt on this platform' unless OpenSSL::KDF.respond_to?(:scrypt)

    implicit = Epithet::Keygen.new(passphrase: 'pw', scrypt: CHEAP)
    explicit = Epithet::Keygen.new(passphrase: 'pw', scrypt: { provider: Epithet::Scrypt::OpenSSL, **CHEAP })

    assert_equal implicit.generate('info', 'salt', 32), explicit.generate('info', 'salt', 32)
  end

  def test_late_registration_wins_automatic_selection
    skip 'Ruby::Box is not enabled' unless defined?(Ruby::Box) && Ruby::Box.enabled?

    box = Ruby::Box.new
    box.load_path.replace($LOAD_PATH)
    box.require('epithet')
    box.eval(<<~RUBY)
      class ConstantIKM < Epithet::Scrypt::Base
        def ikm(passphrase) = "\\xAB".b * length
      end
    RUBY

    expected = OpenSSL::KDF.hkdf("\xAB".b * 32, hash: 'sha256', info: 'info', salt: 'salt', length: 16)
    assert_equal expected, box.eval('Epithet::Keygen.new(passphrase: "sekrit").generate("info", "salt", 16)')
  end
end
