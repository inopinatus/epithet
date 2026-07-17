# frozen_string_literal: true

require 'securerandom'
require 'epithet'

# Using a random passphrase means that epithet identifiers are effectively
# ephemeral, since decoding is limited to the lifetime of this process.
def epithet_initialize
  Epithet.configure(
    passphrase: ENV.fetch('EPITHET_PASSPHRASE') { SecureRandom.random_bytes(32) },
    scrypt: { salt: 'myapp/production' },
    context: 'v1'
  )
end

epithet_initialize
user_epithet = Epithet.new('user')

id = Integer(ARGV.shift || 42)
param = user_epithet.encode(id)

puts "User(#{user_epithet.decode(param)}) => #{param}"
