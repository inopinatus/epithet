# Epithet

Epithet generates stable, compact, purposefully prefixed Base58 identifiers from 64-bit integers for reversible obfuscation and tamper detection.

* https://github.com/inopinatus/epithet
* https://inopinatus.github.io/epithet/

## Installation

Add to your Gemfile:

```ruby
gem 'epithet'
```

Or install directly:

```bash
gem install epithet
```

## Usage

```ruby
require 'epithet'

def epithet_initialize
  Epithet.configure(
    passphrase: ENV.fetch('EPITHET_PASSPHRASE') { 'example only' },
    salt: 'v1'
  )
end

epithet_initialize
user_epithet = Epithet.new('user')

id = 42
param = user_epithet.encode(id)
# => "user_VsuNnfEYQJJTJYE3n28jaY"

user_epithet.decode(param)
# => 42
```

Configuration at initialisation is recommended, because deriving key material from the passphrase uses scrypt, and is consequently expensive. The `salt:` is optional; it's included when deriving the subkey material for obfuscating and tamper resistance, and may be useful for additional context discrimination or during secrets rotation.

Refer to the Epithet rdoc for the full set of configuration options.

Note that `decode` returns `nil` when authentication fails and raises ArgumentError on invalid formats.

## Development

Install dependencies and run tests:

```bash
bundle install
rake test
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/inopinatus/epithet.

## Security considerations

See [`SECURITY.md`](SECURITY.md).

## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
