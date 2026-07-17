# frozen_string_literal: true

require_relative 'test_helper'

# A tripwire for the dup-per-operation cipher/HMAC templates, but not a proof of thread safety.
class EpithetConcurrencyTest < Minitest::Test
  # Overridable so CI can shake harder on runtimes with real thread parallelism.
  THREADS = Integer(ENV.fetch('EPITHET_TEST_THREADS', 8))
  ROUNDS = Integer(ENV.fetch('EPITHET_TEST_ROUNDS', 500))

  def test_disjoint_round_trips_match_serial_ground_truth
    epithet = Epithet.new('user')
    expected = Array.new(THREADS * ROUNDS) { |id| epithet.encode(id) }

    anomalies = hammer do |thread|
      ROUNDS.times.filter_map do |round|
        id = (round * THREADS) + thread
        param = epithet.encode(id)
        [id, param] unless param == expected[id] && epithet.decode(param) == id
      end
    end

    assert_empty anomalies
  end

  def test_contended_encode_and_decode_of_a_single_id
    epithet = Epithet.new('user')
    param = epithet.encode(42)

    anomalies = hammer do
      ROUNDS.times.reject { epithet.encode(42) == param && epithet.decode(param) == 42 }
    end

    assert_empty anomalies
  end

  def test_contended_auth_failure_still_returns_nil
    epithet = Epithet.new('user')
    base = epithet.encode(42).delete_prefix('user_')
    alphabet = Epithet::Block58::Alphabet
    alt = alphabet[(alphabet.index(base[-1]) + 1) % alphabet.length]
    tampered = "user_#{base[0...-1]}#{alt}"

    anomalies = hammer do
      ROUNDS.times.reject { epithet.decode(tampered).nil? }
    end

    assert_empty anomalies
  end

  # Run the block in THREADS threads released together by a latch, and
  # collect/re-raise their anomaly reports via Thread#value.
  def hammer
    latch = Queue.new
    workers = Array.new(THREADS) do |thread|
      Thread.new do
        latch.pop
        yield thread
      end
    end
    THREADS.times { latch << :go }
    workers.flat_map(&:value)
  end
end
