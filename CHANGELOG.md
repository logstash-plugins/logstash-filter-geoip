## 2.0.5
 - Use proper field references

## 2.0.4
 - Refactor GeoIP Struct to hash conversion to minimise repeated manipulation

## 2.0.3
 - Fix Issue 50, incorrect data returned when geo lookup fails

## 2.0.2
 - Update core dependency in gemspec

## 2.0.1
 - Remove filter? call

## 2.0.0
 - Plugins were updated to follow the new shutdown semantic, this mainly allows Logstash to instruct input plugins to terminate gracefully,
   instead of using Thread.raise on the plugins' threads. Ref: https://github.com/elastic/logstash/pull/3895
 - Dependency on logstash-core update to 2.0

* 1.1.2
  - Be more defensive with threadsafety, mostly for specs
* 1.1.1
  - Lazy-load LRU cache
* 1.1.0
  - Add LRU cache
