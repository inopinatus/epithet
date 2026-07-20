# frozen_string_literal: true

require 'openssl'
require 'epithet/scrypt'

class Epithet
  # Key derivation helper
  class Keygen
    # Default parameters for scrypt.
    #
    # ```ruby
    # DEFAULT_SCRYPT_PARAMS = {
    #   salt: 'epithet-default',
    #   N: 1 << 17,
    #   r: 8,
    #   p: 1,
    #   length: 32
    # }.freeze
    # ```
    DEFAULT_SCRYPT_PARAMS = {
      salt: 'epithet-default',
      N: 1 << 17,
      r: 8,
      p: 1,
      length: 32
    }.freeze

    # Create a new key generator from either high-entropy key material, or a supplied passphrase.
    # Supplied scrypt params, if any, are merged over DEFAULT_SCRYPT_PARAMS; `provider:` may name
    # a Scrypt provider class, otherwise one is selected automatically.
    def initialize(ikm: nil, passphrase: nil, digest: 'sha256', scrypt: {})
      if (passphrase.nil? && ikm.nil?) || (!passphrase.nil? && !ikm.nil?)
        raise ArgumentError, 'keygen requires either ikm or passphrase'
      end

      params = DEFAULT_SCRYPT_PARAMS.merge(Hash(scrypt))
      scrypt = (params.delete(:provider) || Scrypt.auto).new(**params)
      @ikm = (ikm&.b || scrypt.ikm(passphrase)).freeze
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
end
