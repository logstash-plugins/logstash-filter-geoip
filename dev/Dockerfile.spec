FROM jruby:1.7

RUN mkdir /opt/logstash-filter-geoip

WORKDIR /opt/logstash-filter-geoip

ADD Gemfile logstash-filter-geoip.gemspec ./

RUN bundle install

ADD Rakefile vendor.json ./

RUN rake vendor

ADD lib lib
ADD spec spec

RUN bundle exec rspec --format documentation

