# frozen_string_literal: true

require_relative 'test_helper'

# A tripwire for the dup-per-operation cipher/HMAC templates
class EpithetConcurrencyTest < Minitest::Test
  THREADS = Integer(ENV.fetch('EPITHET_TEST_THREADS', 8))
  ROUNDS = Integer(ENV.fetch('EPITHET_TEST_ROUNDS', 500))

  def test_disjoint_round_trips_match_serial
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
    assert_equal expected.first, epithet.encode(0)
  end

  def test_parallel_construction_matches_serial
    ground = Epithet.new('user').encode(42)

    anomalies = hammer do
      ROUNDS.times.reject { Epithet.new('user').encode(42) == ground }
    end

    assert_empty anomalies
  end

  def test_contended_round_trips_survive_gc_churn
    epithet = Epithet.new('user')
    param = epithet.encode(42)
    churning = true
    reaper = Thread.new do
      while churning
        began = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        Array.new(512) { +'x' * 64 }
        GC.start(full_mark: false, immediate_sweep: false)
        sleep 4 * (Process.clock_gettime(Process::CLOCK_MONOTONIC) - began) # pacing self-adjustment
      end
    end

    anomalies = hammer do
      ROUNDS.times.reject { epithet.encode(42) == param && epithet.decode(param) == 42 }
    end

    assert_empty anomalies
  ensure
    churning = false
    reaper&.join
  end

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
