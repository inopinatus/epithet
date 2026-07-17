# Epithet

Epithet generates stable, compact, purposefully prefixed base58 identifiers from 64-bit integers for reversible obfuscation and tamper detection.

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

With `EPITHET_PASSPHRASE=example_only`:

```ruby
require 'epithet'

def epithet_initialize
  Epithet.configure(
    passphrase: ENV.fetch('EPITHET_PASSPHRASE'),
    scrypt: { salt: 'myapp/production' },
    context: 'v1'
  )
end

epithet_initialize
user_epithet = Epithet.new('user')

id = 42
param = user_epithet.encode(id)
# => "user_GikJf7Y58t5sgqJpifjgZy"

user_epithet.decode(param)
# => 42
```

Configuration once at initialisation is recommended, because deriving key material from the passphrase uses scrypt, and is consequently expensive.  The `context:` is optional; this parameter is included when deriving the subkey material for obfuscating and tamper resistance, and may be used for separation of purpose or key rotation.  The scrypt step is seasoned by a salt, which defaults to a fixed constant; set an application-specific salt, as in the example above, so that two applications inadvertently sharing a passphrase never derive the same keys.

Refer to the [Epithet rdoc](https://inopinatus.github.io/epithet/) for the full set of configuration options.

Note that `Epithet#decode` returns `nil` when authentication fails, and raises `Epithet::FormatError` (an ArgumentError) on invalid formats.

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
