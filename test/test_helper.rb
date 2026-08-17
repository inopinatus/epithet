# frozen_string_literal: true

$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))

require 'minitest/autorun'

begin
  require 'scrypt'
rescue LoadError
  # optional gem; its provider tests will skip
end

require 'epithet'

Cfg = Epithet::Config.new(passphrase: 'testing')
Epithet.configure(Cfg)
