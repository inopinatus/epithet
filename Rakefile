# frozen_string_literal: true

require 'bundler/setup'
require 'bundler/gem_tasks'
require 'rake/testtask'

task :configure_ruby_box do
  next unless defined?(Ruby::Box) && Ruby::Box.enabled?

  ENV['RUBYOPT'] = [ENV.fetch('RUBYOPT', nil), '--disable-gems'].compact.join(' ')
end

Rake::TestTask.new do |t|
  t.deps << :configure_ruby_box
  t.libs << 'lib'
  t.libs << 'test'
  t.test_files = FileList['test/**/*_test.rb']
  t.warning = true
end

begin
  require 'rdoc/task'

  RDoc::Task.new do |rdoc|
    rdoc.rdoc_files.include('README.md', 'CHANGELOG.md', 'SECURITY.md', 'lib/**/*.rb')
    rdoc.main = 'README.md'
    rdoc.rdoc_dir = 'doc'
    rdoc.generator = 'aliki'
    rdoc.title = 'Epithet RDoc'
    rdoc.markup = 'markdown'
    rdoc.options << '--show-hash'
  end
rescue LoadError
  # rdoc is absent on platforms that cannot build rbs (see Gemfile); no doc task there.
end

task default: :test
