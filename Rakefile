require 'json'

BASE_PATH = File.expand_path(File.dirname(__FILE__))
@files = JSON.parse(File.read(File.join(BASE_PATH, 'vendor.json')))

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
  lsc_path = `bundle show logstash-core`
  lsce_path = `bundle show logstash-core-event`
  FileUtils.rm_f(gradle_properties_file)
  File.open(gradle_properties_file, "w") do |f|
    f.puts "logstashCoreGemPath=#{lsc_path}"
    f.puts "logstashCoreEventGemPath=#{lsce_path}"
  end
  puts "-------------------> Wrote #{gradle_properties_file}"
  puts `cat #{gradle_properties_file}`
end
