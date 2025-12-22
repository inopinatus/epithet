require_relative "test_helper"

class EpithetVectorsTest < Minitest::Test
  # prefix, salt, separator, id, param
  VECTORS = [
    [ "user", "v1", "_", 0, "user_KFoi5HYESM5hxVuNqVXY5K" ],
    [ "user", "v1", "_", 42, "user_Wvj1xHrW4etC4VPvfjhu36" ],
    [ "acct", "v1", "_", 1, "acct_LoYZsysDZFQbE7Ch6HDeBo" ],
    [ "acct", "v2", "_", 1, "acct_75aFU5rhHrrEHmrKWHpShn" ],
    [ "acct", "v2", "_", 0x0123_4567_89ab_cdef, "acct_JSuYHaTtHacG7zBE4WzPmw" ],
    [ nil, nil, nil, 0, "Q6eJGkTY74S1rsfxSHesk7" ],
    [ "", "", "", 0, "Q6eJGkTY74S1rsfxSHesk7" ],
    [ :record, ??, :*, 99, "record*TGB6mATPzzdTwUM8N5VTRw" ],
    [ "record", "?", "*", 99, "record*TGB6mATPzzdTwUM8N5VTRw" ],
    [ "record", "?", "!", 99, "record!TGB6mATPzzdTwUM8N5VTRw" ],
    [ "null\0", "salt", "_", 0, "null\u0000_4t9hVzCcBGzg8rAFDUm7sp" ],
    [ "null", "\0salt", "_", 0, "null_3Mc8ab5abHbvfX97Lgp7XE" ],
  ].freeze

  def test_encode_vectors
    VECTORS.each do |prefix, salt, separator, id, param|
      cfg = Epithet::Config.new(keygen: Cfg.keygen, salt: salt, separator: separator)
      epithet = Epithet.new(prefix, config: cfg)

      assert_equal param, epithet.encode(id)
    end
  end

  def test_decode_vectors
    VECTORS.each do |prefix, salt, separator, id, param|
      cfg = Epithet::Config.new(keygen: Cfg.keygen, salt: salt, separator: separator)
      epithet = Epithet.new(prefix, config: cfg)

      assert_equal id, epithet.decode(param)
    end
  end
end
