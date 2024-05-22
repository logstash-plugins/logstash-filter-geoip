## 7.3.0
  - Added support for MaxMind GeoIP2 Enterprise and Anonymous-IP databases ([#223](https://github.com/logstash-plugins/logstash-filter-geoip/pull/223))
  - Updated MaxMind dependencies.
  - Added tests for the Java classes.

## 7.2.13
  - [DOC] Add documentation for database auto-update configuration [#210](https://github.com/logstash-plugins/logstash-filter-geoip/pull/210)

## 7.2.12
  - [DOC] Add `http_proxy` environment variable for GeoIP service endpoint. The feature is included in 8.1.0, and was back-ported to 7.17.2 [#207](https://github.com/logstash-plugins/logstash-filter-geoip/pull/207) 

## 7.2.11
  - Improved compatibility with the Elastic Common Schema [#206](https://github.com/logstash-plugins/logstash-filter-geoip/pull/206)
    - Added support for ECS's composite `region_iso_code` (`US-WA`), which _replaces_ the non-ECS `region_code` (`WA`) as a default field with City databases. To get the stand-alone `region_code` in ECS mode, you must include it in the `fields` directive. 
    - [DOC] Improve ECS-related documentation

## 7.2.10
  - [DOC] Air-gapped environment requires both ASN and City databases [#204](https://github.com/logstash-plugins/logstash-filter-geoip/pull/204)

## 7.2.9
  - Fix: red CI in Logstash 8.0 [#201](https://github.com/logstash-plugins/logstash-filter-geoip/pull/201)
  - Update Log4j dependency to 2.17.1

## 7.2.8
  - Update Log4j dependency to 2.17.0

## 7.2.7
  - Ensure java 8 compatibility [#197](https://github.com/logstash-plugins/logstash-filter-geoip/pull/197)

## 7.2.6
  - Update Log4J dependencies [#196](https://github.com/logstash-plugins/logstash-filter-geoip/pull/196)

## 7.2.5
  - Added preview of ECS-v8 support with existing ECS-v1 implementation [#193](https://github.com/logstash-plugins/logstash-filter-geoip/pull/193)

## 7.2.4
  - Fix: update to Gradle 7 [#191](https://github.com/logstash-plugins/logstash-filter-geoip/pull/191)
  - [DOC] Clarify CC licensed database indefinite use condition and air-gapped environment [#192](https://github.com/logstash-plugins/logstash-filter-geoip/pull/192)

## 7.2.3
  - [DOC] Add documentation for bootstrapping air-gapped environment for database auto-update [#189](https://github.com/logstash-plugins/logstash-filter-geoip/pull/189)

## 7.2.2
  - [DOC] Add documentation for database auto-update behavior and database metrics [#187](https://github.com/logstash-plugins/logstash-filter-geoip/pull/187)

## 7.2.1
  - Republish the gem due to missing jars in 7.2.0 [#186](https://github.com/logstash-plugins/logstash-filter-geoip/pull/186)

## 7.2.0
  - YANKED
  - Add EULA GeoIP2 Database with auto-update [#181](https://github.com/logstash-plugins/logstash-filter-geoip/pull/181)
    Available in Logstash 7.14+
  - Support multiple pipelines using the same database
  - Add EULA doc

## 7.1.3
  - Fixed resolving wrong `fields` name `AUTONOMOUS_SYSTEM_NUMBER` and `AUTONOMOUS_SYSTEM_ORGANIZATION` [#185](https://github.com/logstash-plugins/logstash-filter-geoip/pull/185)

## 7.1.2
  - Remove EULA doc as MaxMind auto-update has been retargeted to a later release [#183](https://github.com/logstash-plugins/logstash-filter-geoip/pull/183)

## 7.1.1
  - Changed the behaviour of database expiry. Instead of stopping the pipeline, it adds a tag `_geoip_expired_database` [#182](https://github.com/logstash-plugins/logstash-filter-geoip/pull/182)

## 7.1.0
  - Add ECS compatibility [#179](https://github.com/logstash-plugins/logstash-filter-geoip/pull/179)

## 7.0.1
  - [DOC] Add documentation for MaxMind database license change [#177](https://github.com/logstash-plugins/logstash-filter-geoip/pull/177)

## 7.0.0
  - Changed the plugin to use EULA GeoIP2 Database with auto-update [#176](https://github.com/logstash-plugins/logstash-filter-geoip/pull/176)
    Available in Logstash 7.13+ Elastic license

## 6.0.5
  - Fix database download task. Upgrade project to java 11 [#175](https://github.com/logstash-plugins/logstash-filter-geoip/pull/175)

## 6.0.4
  - Enable the use of MaxMind GeoIP2-Domain databases [#162](https://github.com/logstash-plugins/logstash-filter-geoip/pull/162)

## 6.0.3
  - Fixed docs for missing region_code [#158](https://github.com/logstash-plugins/logstash-filter-geoip/pull/158)

## 6.0.2
  - Update of GeoLite2 DB [#157](https://github.com/logstash-plugins/logstash-filter-geoip/pull/157)

## 6.0.1
  - Fixed deeplink to Elasticsearch Reference 
  [#151](https://github.com/logstash-plugins/logstash-filter-geoip/pull/151)

## 6.0.0
  - Removed obsolete lru_cache_size field

## 5.0.3
 - Skip lookup operation if source field contains an empty string 
 - Update of the GeoIP2 DB

## 5.0.2
  - Update gemspec summary

## 5.0.1
  - Fix some documentation issues

## 5.0.0
  - Make deprecated field lru_cache_size obsolete

## 4.3.0
  - Bundle the GeoLite2-ASN database by default
  - Add default_database_type configuration option to allow selection between the GeoLite2-City and GeoLote2-ASN databases.

## 4.2.0
  - Add support for GeoLite2-ASN database from MaxMind for ASN data.
  - Update Java dependencies to 2.9.0 to support the new ASN database.

## 4.1.1
  - Add support for commercial databases from MaxMind.
  - Add ASN data support via GeoIP2-ISP database.
  
## 4.1.0
  - Removed from RubyGems.org since it was missing the default GeoIP2 database.  

## 4.0.6
  - Docs: Remove patch classes from the main plugin file
  - Update of the GeoIP2 DB

## 4.0.5
  - Docs: Clarify GeoLite2 database support
  
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
