# frozen_string_literal: true

require 'openssl'

class Epithet
  # Provider registry & classes for the scrypt implementations.
  #
  # A scrypt provider is any class that can be instantiated with the scrypt
  # parameters `salt`, `N`, `r`, `p`, and `length`, an instance method
  # `ikm(passphrase)` that derives the key material, and a predicate method
  # `auto?` indicating willingness to operate.  Subclassing Epithet::Scrypt::Base
  # auto-registers the subclass as a provider.  Automatic selection takes the
  # most recently registered willing provider.
  #
  # Of the builtin providers, we prefer `OpenSSL::KDF.scrypt` when the platform
  # supplies it, then JRuby's BouncyCastle implementation, and finally an
  # already-loaded [`scrypt`](https://rubygems.org/gems/scrypt) gem.  If none of
  # these are available, selection falls through to a base class which raises
  # `NotImplementedError` at the point of use.
  #
  # Epithet deliberately does not require the optional `scrypt` gem itself; an
  # application relying on the SCryptGem provider must bundle and require `scrypt`
  # before requiring `epithet`.
  #
  # You may register a custom scrypt provider via the same pattern, even after
  # Epithet has loaded:
  #
  #     class MyProvider < Epithet::Scrypt::Base
  #       def ikm(passphrase)
  #         #...
  #       end
  #     end
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
    class << self
      def known = @known ||= []
      def register(klass) = known.unshift(klass)
      def auto = known.detect(&:auto?)
    end

    # Define contract params & last resort behaviour.
    Base = Data.define(:salt, :N, :r, :p, :length) do          # rubocop:disable Naming/MethodName
      def self.inherited(subclass) = Scrypt.register(subclass) # rubocop:disable Lint/MissingSuper
      def self.auto? = true
      def ikm(passphrase) = raise NotImplementedError, 'no scrypt available'
      Scrypt.register(self)
    end

    # May be useful when using LibreSSL and other OpenSSLs that lack scrypt.
    class SCryptGem < Base
      def self.auto? = defined? ::SCrypt::Engine

      def ikm(passphrase)
        ::SCrypt::Engine.scrypt(passphrase, salt, self.N, r, p, length)
      end
    end

    # JRuby's "openssl" is actually a BouncyCastle wrapper.  That wrapper doesn't
    # expose BouncyCastle's scrypt, so we do it ourselves.
    class BouncyCastle < Base
      def self.auto? = RUBY_ENGINE == 'jruby'

      def ikm(passphrase)
        String.from_java_bytes(
          Java::OrgBouncycastleCryptoGenerators::SCrypt.generate(
            passphrase.to_java_bytes, salt.to_java_bytes, self.N, r, p, length
          )
        )
      end
    end

    # Default, preferred, OpenSSL as scrypt provider.
    class OpenSSL < Base
      def self.auto? = ::OpenSSL::KDF.respond_to? :scrypt

      def ikm(passphrase)
        ::OpenSSL::KDF.scrypt(passphrase, **to_h)
      end
    end
  end
end
