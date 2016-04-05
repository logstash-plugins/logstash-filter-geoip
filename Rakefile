require 'json'

BASE_PATH = File.expand_path(File.dirname(__FILE__))
@files = JSON.parse(File.read(File.join(BASE_PATH, 'vendor.json')))

task :default do
  system("rake -T")
end

require 'jars/installer'
task :install_jars do
  ENV['JARS_HOME'] = Dir.pwd + "/vendor/jar-dependencies/runtime-jars"
  ENV['JARS_VENDOR'] = "false"
  Jars::Installer.vendor_jars!
end

require "logstash/devutils/rake"
