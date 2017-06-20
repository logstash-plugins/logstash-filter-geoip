#!/bin/bash
current_dir="$(dirname "$0")"

bundle install
bundle exec rake gradle.properties
./gradlew assemble
bundle exec rake vendor

# we don't want to bundle ASN DB with this gem, so we download this just for tests.
curl -sL http://geolite.maxmind.com/download/geoip/database/GeoLite2-ASN.tar.gz > GeoLite2-ASN.tar.gz
tar -xzf GeoLite2-ASN.tar.gz --strip-components=1 -C $current_dir/../vendor/.

./gradlew test
bundle exec rspec spec
