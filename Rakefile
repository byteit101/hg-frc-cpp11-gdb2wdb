#
# To change this template, choose Tools | Templates
# and open the template in the editor.


require 'rubygems'
require 'rake'
require 'rake/clean'
require 'rubygems/package_task'

spec = Gem::Specification.new do |s|
  s.name = 'gdb2wdb'
  s.version = '1.0'
  s.has_rdoc = false
  s.extra_rdoc_files = ['README', 'LICENSE']
  s.summary = 'VxWorks debug bridge'
  s.description = "GDB (RSP) to WDB server to enable debugging VxWorks kernel modules"
  s.author = 'Patrick Plenefisch'
  s.email = 'simonpatp@gmail.com'
  s.executables = ['gdb2wdb']
  s.files = %w(LICENSE README Rakefile) + Dir.glob("{bin,lib,spec}/**/*")
  s.require_path = "lib"
  s.bindir = "bin"
  s.add_dependency "trollop"
  s.homepage = "http://firstforge.wpi.edu/sf/wiki/do/viewPage/projects.c--11_toochain/wiki/GDB"
end

Gem::PackageTask.new(spec) do |p|
  p.gem_spec = spec
  p.need_tar = true
  p.need_zip = true
end
