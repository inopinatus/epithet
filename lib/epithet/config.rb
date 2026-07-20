# frozen_string_literal: true

require 'openssl'
require 'epithet/block58'
require 'epithet/keygen'

class Epithet
  # Class for passing around preset configs. See Epithet::configure for options.
  class Config
    attr_reader :keygen, :context, :separator, :cipher, :digest, :codec # :nodoc:

    def initialize(opts = {})
      opts = opts.dup
      @separator = -String(opts.delete(:separator) { '_' })
      @context = -String(opts.delete(:context))
      alphabet = String(opts.delete(:alphabet) { Block58::Alphabet })
      @cipher = -(opts.delete(:cipher) || 'aes-256-ecb').downcase
      @digest = -(opts.delete(:digest) || 'sha256').downcase
      keygen, passphrase, scrypt = %i[keygen passphrase scrypt].map { opts.delete it }

      cipher = probe(OpenSSL::Cipher, @cipher)
      digest = probe(OpenSSL::Digest, @digest)

      raise ArgumentError, 'separator intersects alphabet' if @separator.bytes.intersect?(alphabet.bytes)
      raise ArgumentError, "#{@cipher} not a 128-bit block cipher" if cipher.block_size != 16
      raise ArgumentError, "#{@cipher} requires an IV/nonce" if cipher.iv_len != 0
      raise ArgumentError, "#{@digest} produces < 64-bit digest" if digest.digest_length < 8
      raise ArgumentError, 'use keygen: or passphrase:, not both' if keygen && (passphrase || scrypt)
      raise ArgumentError, 'one of passphrase: or keygen: is required' unless keygen || passphrase
      raise ArgumentError, "unused option(s) #{opts.keys}" unless opts.empty?

      @codec = Block58.build(cipher.block_size, alphabet:)
      @keygen = keygen || Keygen.new(passphrase:, digest: @digest, scrypt:)
      freeze
    end

    # The openssl gem <4.0 raises bare RuntimeError for unrecognised algorithm
    # names; jruby-openssl raises NotImplementedError.
    def probe(kind, name) # :nodoc:
      kind.new(name)
    rescue OpenSSL::OpenSSLError, RuntimeError, NotImplementedError
      raise ArgumentError, "unknown #{kind.name[/\w+\z/].downcase} #{name}"
    end
  end
end
