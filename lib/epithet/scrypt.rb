# frozen_string_literal: true

require 'openssl'
require 'monitor'

class Epithet
  # Provider registry & classes for the scrypt implementations.
  #
  # A scrypt provider is any class that can be instantiated with the scrypt
  # parameters `salt`, `N`, `r`, `p`, and `length`, has a predicate singleton
  # method `auto?` indicating willingness to operate, and an instance method
  # `ikm(passphrase)` that derives the key material.  Automatic selection picks
  # the most recently registered willing provider.
  #
  # Of the builtin providers, we prefer `OpenSSL::KDF.scrypt` when the platform
  # supplies it, then JRuby's BouncyCastle implementation, and finally an
  # already-loaded [`scrypt`](https://rubygems.org/gems/scrypt) gem.  If none of
  # these are available, selection falls through to a base class which raises
  # `NotImplementedError` at the point of use.
  #
  # Epithet deliberately does not require the optional `scrypt` gem itself; an
  # application relying on the `SCryptGem` provider should bundle and require
  # `scrypt` before configuring Epithet.
  #
  # You may register a custom scrypt provider with the necessary signature, even
  # after Epithet has loaded:
  #
  #     class MyProvider < Epithet::Scrypt::Base
  #       def ikm(passphrase)
  #         #...
  #       end
  #     end
  #     Epithet::Scrypt.register(MyProvider)
  #
  # and this will be unconditionally preferred unless you also define a selective
  # `auto?` method.
  #
  # Your `ikm` method should return `length` bytes of key material.
  #
  # Using this mechanism as a hook to deviate from the scrypt algorithm is not
  # recommended; the better move would be to substitute a variant key
  # generator in the `Epithet::Config` parameters, or supply IKM to an
  # `Epithet::Keygen`.
  module Scrypt
    extend MonitorMixin

    class << self
      # The registered providers, in automatic-selection order.
      def providers = synchronize { @providers }

      # Registers `klass` ahead of the existing providers.
      def register(klass) = synchronize { @providers = [klass, *@providers].freeze }

      # Returns the first registered provider willing to operate.
      def auto = providers.detect(&:auto?)

      # Instantiates the automatically selected provider.
      def new(...) = auto.new(...)
    end

    # :section: Providers
    #
    # ### `Base` class
    #
    # Defines the common `salt`, `N`, `r`, `p`, and `length` parameters.  It is
    # the last-resort provider: `ikm(passphrase)` raises `NotImplementedError`
    # when no scrypt implementation is available.
    #
    # ### `OpenSSL` class
    #
    # The default, preferred provider.  It uses `OpenSSL::KDF.scrypt` when the
    # platform's OpenSSL supplies it.
    #
    # ### `BouncyCastle` class
    #
    # The JRuby fallback.  JRuby's `openssl` is a BouncyCastle wrapper, but does
    # not expose BouncyCastle's scrypt, so this provider invokes it directly.
    #
    # ### `SCryptGem` class
    #
    # A fallback for LibreSSL and other OpenSSLs that lack scrypt.  It is
    # available when the application has already loaded the optional
    # [`scrypt`](https://rubygems.org/gems/scrypt) gem.
    Base = Data.define(:salt, :N, :r, :p, :length) do # :nodoc: # rubocop:disable Naming/MethodName
      def self.auto? = true
      def ikm(passphrase) = raise NotImplementedError, 'no scrypt available'
    end

    class SCryptGem < Base # :nodoc:
      def self.auto? = defined? ::SCrypt::Engine

      def ikm(passphrase)
        ::SCrypt::Engine.scrypt(passphrase, salt, self.N, r, p, length)
      end
    end

    class BouncyCastle < Base # :nodoc:
      def self.auto? = RUBY_ENGINE == 'jruby'

      def ikm(passphrase)
        String.from_java_bytes(
          Java::OrgBouncycastleCryptoGenerators::SCrypt.generate(
            passphrase.to_java_bytes, salt.to_java_bytes, self.N, r, p, length
          )
        )
      end
    end

    class OpenSSL < Base # :nodoc:
      def self.auto? = ::OpenSSL::KDF.respond_to? :scrypt

      def ikm(passphrase)
        ::OpenSSL::KDF.scrypt(passphrase, **to_h)
      end
    end

    @providers = [OpenSSL, BouncyCastle, SCryptGem, Base].freeze
  end
end
