## 4.0.4
  - Update of the GeoIP2 DB
  - Target should be merged and not completely overwritten (#98)

## 4.0.3
  - Update of the GeoIP2 DB

## 4.0.2
  - Recreate gem since 4.0.1 lacked jars

## 4.0.1
  - Relax constraint on logstash-core-plugin-api to >= 1.60 <= 2.99

## 4.0.0
  - Update the plugin to the version 2.0 of the plugin api, this change is required for Logstash 5.0 compatibility. See https://github.com/elastic/logstash/issues/5141
  - GA release for GeoIP2 database, compatible with LS 5.x

# 3.0.0-beta3
 - Return empty result when IP lookup fails for location field (#70)

# 3.0.0-beta2
 - Internal: Actually include the vendored jars

# 3.0.0-beta1
 - Changed plugin to use GeoIP2 database. See http://dev.maxmind.com/geoip/geoip2/whats-new-in-geoip2/

# 2.0.7
  - Depend on logstash-core-plugin-api instead of logstash-core, removing the need to mass update plugins on major releases of logstash
# 2.0.6
  - New dependency requirements for logstash-core for the 5.0 release
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
