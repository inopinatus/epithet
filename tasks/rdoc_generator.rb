# frozen_string_literal: true

require 'rdoc'
require 'rdoc/generator/aliki'

module RDoc
  module Generator
    # Aliki, but listing the README in the page index.
    #
    # RDoc 8 renders the main page as index.html, then skips its own file and
    # excludes it from the Pages nav, so README_md.html becomes a 404.  Here
    # the README stays listed, rdoc still resolves it to index.html, and the
    # former URL survives as a static redirect the Rakefile copies into place.
    # We mostly reuse Aliki's templates but patch the sidebar partial in a
    # tmpdir to slot it in at runtime.
    class Epithet < Aliki
      DESCRIPTION = 'Aliki, with the main page listed'

      def self.setup_options(options)
        options.template ||= 'aliki'
        options.template_dir ||= options.template_dir_for options.template
      end

      def generate
        Pathname.mktmpdir do |dir|
          (@template_dir + pages_partial).open do |source|
            remove_sidebar_skip!(source.read).then { (dir + pages_partial).write(it) }
          end
          @patch_dir = dir
          super
        end
      end

      def render(file)
        file == pages_partial ? with_patch_dir { super } : super
      end

      private

      def pages_partial = '_sidebar_pages.rhtml'

      def remove_sidebar_skip!(s)
        s.sub! %(f.text? && f.full_name != @options.main_page),
               %(f.text?) or raise Error, "#{pages_partial} template patch failed"
      end

      def with_patch_dir
        original, @template_dir = @template_dir, @patch_dir
        yield
      ensure
        @template_dir = original
      end

      RDoc.add_generator self
    end
  end
end
