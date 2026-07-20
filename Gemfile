# frozen_string_literal: true

source 'https://rubygems.org'

gemspec

# Current rdoc depends on rbs, whose C extension JRuby cannot build.
# The scrypt gem exercises its optional provider adapter.
platforms :ruby do
  gem 'rdoc', github: 'inopinatus/rdoc', branch: 'restore-main-page-url'
  gem 'scrypt', '>= 3'
end
