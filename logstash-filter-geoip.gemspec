Gem::Specification.new do |s|

  s.name            = 'logstash-filter-geoip'
  s.version         = '4.0.6'
  s.licenses        = ['Apache License (2.0)']
  s.summary         = "$summary"
  s.description     = "This gem is a Logstash plugin required to be installed on top of the Logstash core pipeline using $LS_HOME/bin/logstash-plugin install gemname. This gem is not a stand-alone program"
  s.authors         = ["Elastic"]
  s.email           = 'info@elastic.co'
  s.homepage        = "http://www.elastic.co/guide/en/logstash/current/index.html"
  s.require_paths = ["lib"]
  s.platform      = "java"

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT', 'maxmind-db-NOTICE.txt']

  # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", ">= 1.60", "<= 2.99"

  s.requirements << "jar com.maxmind.geoip2:geoip2, 2.5.0, :exclusions=> [com.google.http-client:google-http-client]"

  s.add_development_dependency "jar-dependencies"

  s.add_development_dependency 'ruby-maven', '~> 3.3'

  s.add_development_dependency 'logstash-devutils'
end
