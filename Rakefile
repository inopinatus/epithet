require "bundler/setup"
require 'bundler/gem_tasks'
require "rake/testtask"
require 'rdoc/task'

Rake::TestTask.new do |t|
  t.libs << "lib"
  t.libs << "test"
  t.test_files = FileList["test/**/*_test.rb"]
  t.warning = true
end

RDoc::Task.new do |rdoc|
  rdoc.main = "README.md"
  rdoc.rdoc_files.include("README.md", "CHANGELOG.md", "SECURITY.md", "lib/**/*.rb")
  rdoc.rdoc_dir = 'doc'
  rdoc.generator = 'aliki'
  rdoc.title = 'Epithet RDoc'
  rdoc.markup = 'markdown'
end

task default: :test
