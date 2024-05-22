package org.logstash.filters.geoip;

import java.nio.file.Path;
import java.nio.file.Paths;

abstract class MaxMindDatabases {
    private MaxMindDatabases() { /* empty */ }

    private static final Path DB_PATH = Paths.get("src/test/resources/maxmind-test-data");

    static final Path GEOIP2_ANONYMOUS_IP = DB_PATH.resolve("GeoIP2-Anonymous-IP-Test.mmdb");
    static final Path GEOIP2_CITY = DB_PATH.resolve("GeoIP2-City-Test.mmdb");
    static final Path GEOIP2_COUNTRY = DB_PATH.resolve("GeoIP2-Country-Test.mmdb");
    static final Path GEOIP2_DOMAIN = DB_PATH.resolve("GeoIP2-Domain-Test.mmdb");
    static final Path GEOIP2_ENTERPRISE = DB_PATH.resolve("GeoIP2-Enterprise-Test.mmdb");
    static final Path GEOIP2_ISP = DB_PATH.resolve("GeoIP2-ISP-Test.mmdb");
    static final Path GEOLITE2_ASN = DB_PATH.resolve("GeoLite2-ASN-Test.mmdb");
    static final Path GEOLITE2_CITY = DB_PATH.resolve("GeoLite2-City-Test.mmdb");
    static final Path GEOLITE2_COUNTRY = DB_PATH.resolve("GeoLite2-Country-Test.mmdb");
}
