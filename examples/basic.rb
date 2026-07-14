# frozen_string_literal: true

require 'epithet'

def epithet_initialize
  Epithet.configure(
    passphrase: ENV.fetch('EPITHET_PASSPHRASE') { 'example only' },
    salt: 'v1'
  )
end

epithet_initialize
user_epithet = Epithet.new('user')

id = Integer(ARGV.shift || 42)
param = user_epithet.encode(id) #=> "user_VsuNnfEYQJJTJYE3n28jaY"

puts "User(#{user_epithet.decode(param)}) => #{param}"
