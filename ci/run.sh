#!/bin/bash
current_dir="$(dirname "$0")"

bundle install
bundle exec rake gradle.properties
./gradlew assemble
bundle exec rake vendor
./gradlew test
bundle exec rspec spec
