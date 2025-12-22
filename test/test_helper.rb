$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))

require 'minitest/autorun'
require 'epithet'

Cfg = Epithet::Config.new(passphrase: 'testing')
Epithet.configure(Cfg)
