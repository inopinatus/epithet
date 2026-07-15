# frozen_string_literal: true

require_relative 'test_helper'

class EpithetVectorsTest < Minitest::Test
  # rubocop:disable Layout/LineLength, Metrics/ParameterLists
  # prefix, context, separator, id, param, {algo opts}
  VECTORS = [
    ['user', 'v1', '_', 0, 'user_Hx94sDMhq5ApcA6Fn4fFAu'],
    ['user', 'v1', '_', 42, 'user_KSF2PhUExdzyb5H2Q1o1fT'],
    ['user', 'v1', '_', 0xffff_ffff, 'user_56Luj9bM8j8Vh4ozWTjVKB'],
    ['user', 'v1', '_', 0x1_0000_0000, 'user_HBodEDmRAt9LE7rzNS93Dn'],
    ['user', 'v1', '_', 0xffff_ffff_ffff_ffff, 'user_4oxc76QX1GM6ThCtsP7Gur'],
    ['acct', 'v1', '_', 1, 'acct_SGunL8c5i7PUCKZCKHePyn'],
    ['acct', 'v2', '_', 1, 'acct_Dc4buC7NCZvuYQuRQmCSnf'],
    ['acct', 'v2', '_', 0x0123_4567_89ab_cdef, 'acct_Qczj4jtqPgN5SKX3gao7YQ'],
    [nil, nil, nil, 0, '6dvBXpPNczQM2aswd7XHKx'],
    [nil, nil, '_', 0, '6dvBXpPNczQM2aswd7XHKx'],
    ['', '', '', 0, '6dvBXpPNczQM2aswd7XHKx'],
    ['', nil, '_', 0, '6dvBXpPNczQM2aswd7XHKx'],
    [:record, ??, :*, 99, 'record*VFgrETepREGumQiD6bfbeA'],
    ['record', ??, '*', 99, 'record*VFgrETepREGumQiD6bfbeA'],
    ['record', ??, '!', 99, 'record!VFgrETepREGumQiD6bfbeA'],
    ["null\0", 'salt', '_', 0, "null\u0000_5LQZh7LTH5ELCef2myFrxs"],
    ['null', "\0salt", '_', 0, 'null_5nxxNksUtvNzRoBGu7KFzN'],
    ['user', 'v1', '_', 99, 'user_15nsx8ynqoQZkF7ECd3RXC', { cipher: nil, digest: nil }],
    ['user', 'v1', '_', 99, 'user_15nsx8ynqoQZkF7ECd3RXC', { cipher: 'AES-256-ECB', digest: 'SHA256' }],
    ['user', 'v1', '_', 42, 'user_GykGNNtyVs5dkT6BnBBsA4', { cipher: 'camellia-256-ecb' }],
    ['user', 'v1', '_', 42, 'user_NT4SAGD3BVK5q26cTUVvCN', { digest: 'sha224' }],
    ['user', 'v1', '_', 42, 'user_1vR83aBboYcj3PUdVKdYvP', { cipher: 'camellia-256-ecb', digest: 'sha224' }],
    ['user', 'v1', '_', 42, 'user_1vR83aBboYcj3PUdVKdYvP', { cipher: 'CAMELLIA-256-ECB', digest: 'SHA224' }],
    ['user', 'v1', '_', 0xffff_ffff_ffff_ffff, 'user_WGkaPfqzS4R7C6LRWBWZYF', { cipher: 'aes-128-ecb', digest: 'sha512' }],
  ].freeze

  def test_encode_vectors
    VECTORS.each do |prefix, context, separator, id, param, algo|
      cfg = Epithet::Config.new(keygen: Cfg.keygen, context:, separator:, **algo)
      epithet = Epithet.new(prefix, config: cfg)

      assert_equal param, epithet.encode(id)
    end
  end

  def test_decode_vectors
    VECTORS.each do |prefix, context, separator, id, param, algo|
      cfg = Epithet::Config.new(keygen: Cfg.keygen, context:, separator:, **algo)
      epithet = Epithet.new(prefix, config: cfg)

      assert_equal id, epithet.decode(param)
    end
  end
  # rubocop:enable Layout/LineLength, Metrics/ParameterLists
end
