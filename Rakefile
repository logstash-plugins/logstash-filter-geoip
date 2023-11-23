require 'json'

BASE_PATH = File.expand_path(File.dirname(__FILE__))

task :default do
  system("rake -T")
end

require "logstash/devutils/rake"

task :vendor => :gradle

task :gradle => "gradle.properties" do
  system("./gradlew vendor")
end

file "gradle.properties" do
  delete_create_gradle_properties
end

def delete_create_gradle_properties
  root_dir = File.dirname(__FILE__)
  gradle_properties_file = "#{root_dir}/gradle.properties"
  # find the path to the logstash-core gem
  lsc_path = Bundler.rubygems.find_name("logstash-core").first.full_gem_path
  FileUtils.rm_f(gradle_properties_file)
  File.open(gradle_properties_file, "w") do |f|
    f.puts "logstashCoreGemPath=#{lsc_path}"
  end
  puts "-------------------> Wrote #{gradle_properties_file}"
  puts `cat #{gradle_properties_file}`
end
