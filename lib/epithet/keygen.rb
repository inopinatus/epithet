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

    # Create a new key generator from a supplied passphrase, or from high-entropy initial key
    # material if already prepared.  The passphrase will be hashed with scrypt.  Supplied scrypt
    # params, if any, are merged over DEFAULT_SCRYPT_PARAMS, so this works:
    #
    #     Epithet::Keygen.new(
    #       passphrase: ENV.fetch('EPITHET_PASSPHRASE'),
    #       scrypt: { salt: "#{MyApp.name}/#{MyApp.env}" }
    #     )
    #
    # A scrypt provider will be chosen by `Epithet::Scrypt.auto`.  To override automatic selection
    # and use a specific scrypt provider, pass it as `provider` in the scrypt parameters:
    #
    #     kg = Epithet::Keygen.new(passphrase: 'pw', scrypt: { provider: Epithet::Scrypt::OpenSSL })
    #
    # but this should be unnecessary in the common case.
    def initialize(ikm: nil, passphrase: nil, digest: 'sha256', scrypt: {})
      raise ArgumentError, 'keygen requires either ikm or passphrase' unless passphrase.nil? ^ ikm.nil?

      @ikm = (ikm&.b || build_scrypt(Hash(scrypt)).ikm(passphrase)).freeze
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

    private

    def build_scrypt(opts)
      params = DEFAULT_SCRYPT_PARAMS.merge(opts)
      (params.delete(:provider) || Scrypt.auto).new(**params)
    end
  end
end
