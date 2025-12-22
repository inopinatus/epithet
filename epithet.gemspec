require_relative "lib/epithet/version"

Gem::Specification.new do |spec|
  spec.name = "epithet"
  spec.version = Epithet::VERSION
  spec.summary = "External base58 identifiers with reversible, authenticated obfuscation."
  spec.description = "Epithet generates stable, prefixed, Base58 identifiers from 64-bit integers using AES and HMAC."
  spec.authors = ["Josh Goodall"]
  spec.email = ["inopinatus@hey.com"]
  spec.license = "MIT"
  spec.homepage = 'https://github.com/inopinatus/epithet'
  spec.files = Dir["lib/**/*", "examples/**/*", "LICENSE", "README.md", "CHANGELOG.md", "SECURITY.md"]
  spec.require_paths = ["lib"]
  spec.required_ruby_version = '>= 3'
  spec.metadata = {
    "homepage_uri" => "https://inopinatus.github.io/epithet/",
    "source_code_uri" => "https://github.com/inopinatus/epithet",
    "changelog_uri" => "https://github.com/inopinatus/epithet/blob/main/CHANGELOG.md",
    "bug_tracker_uri" => "https://github.com/inopinatus/epithet/issues",
    "rubygems_mfa_required" => "true"
  }
  spec.add_development_dependency "minitest"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "rdoc", '>= 7'
end
