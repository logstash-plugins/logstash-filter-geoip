package org.logstash.filters.geoip;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

enum Databases {

    CITY(
            "City",
            EnumSet.of(
                    Fields.IP,
                    Fields.CITY_NAME,
                    Fields.CONTINENT_CODE,
                    Fields.COUNTRY_NAME,
                    Fields.COUNTRY_CODE2,
                    Fields.COUNTRY_CODE3,
                    Fields.POSTAL_CODE,
                    Fields.DMA_CODE,
                    Fields.REGION_NAME,
                    Fields.REGION_ISO_CODE,
                    Fields.TIMEZONE,
                    Fields.LOCATION,
                    Fields.LATITUDE,
                    Fields.LONGITUDE
            )
    ),
    COUNTRY(
            "Country",
            EnumSet.of(
                    Fields.IP,
                    Fields.COUNTRY_CODE2,
                    Fields.COUNTRY_NAME,
                    Fields.CONTINENT_NAME
            )
    ),
    DOMAIN(
            "GeoIP2-Domain",
            EnumSet.of(
                    Fields.DOMAIN
            )
    ),
    ASN(
            "GeoLite2-ASN",
            EnumSet.of(
                    Fields.IP,
                    Fields.AUTONOMOUS_SYSTEM_NUMBER,
                    Fields.AUTONOMOUS_SYSTEM_ORGANIZATION
            )
    ),
    ISP(
            "GeoIP2-ISP",
            EnumSet.of(
                    Fields.IP,
                    Fields.AUTONOMOUS_SYSTEM_NUMBER,
                    Fields.AUTONOMOUS_SYSTEM_ORGANIZATION,
                    Fields.ISP,
                    Fields.ORGANIZATION
            )
    ),
    ANONYMOUS_IP(
            "GeoIP2-Anonymous-IP",
            EnumSet.of(
                    Fields.HOSTING_PROVIDER,
                    Fields.TOR_EXIT_NODE,
                    Fields.ANONYMOUS_VPN,
                    Fields.ANONYMOUS,
                    Fields.PUBLIC_PROXY,
                    Fields.RESIDENTIAL_PROXY
            )
    ),
    ENTERPRISE(
            "Enterprise",
            EnumSet.of(
                    Fields.IP,
                    Fields.COUNTRY_CODE2,
                    Fields.COUNTRY_NAME,
                    Fields.CONTINENT_NAME,
                    Fields.REGION_ISO_CODE,
                    Fields.REGION_NAME,
                    Fields.CITY_NAME,
                    Fields.LOCATION
            )
    ),
    UNKNOWN(
            "Unknown",
            EnumSet.noneOf(Fields.class)
    );

    private final String databaseType;
    private final Set<Fields> defaultFields;

    Databases(String databaseType, final Set<Fields> defaultFields) {
        this.databaseType = databaseType;
        this.defaultFields = defaultFields;
    }

    public Set<Fields> getDefaultFields() {
        return Collections.unmodifiableSet(defaultFields);
    }

    public static Databases fromDatabaseType(final String type) {
        // It follows the same com.maxmind.geoip2.DatabaseReader#getDatabaseType logic
        if (type.contains(CITY.databaseType)) {
            return Databases.CITY;
        } else if (type.contains(COUNTRY.databaseType)) {
            return Databases.COUNTRY;
        } else if (type.contains(DOMAIN.databaseType)) {
            return Databases.DOMAIN;
        } else if (type.contains(ASN.databaseType)) {
            return Databases.ASN;
        } else if (type.contains(ISP.databaseType)) {
            return Databases.ISP;
        } else if (type.contains(ENTERPRISE.databaseType)) {
            return Databases.ENTERPRISE;
        } else if (type.contains(ANONYMOUS_IP.databaseType)) {
            return Databases.ANONYMOUS_IP;
        }

        // Maybe, we should throw and exception here instead of use an unknown database type.
        // It will end up failing on the GeoIPFilter#handleEvent anyway, and the reason why
        // we have this UNKNOWN type here, is to keep it backward compatible, allowing the pipeline
        // to start, even if the plugin is configured to a non Logstash supported database type.
        return Databases.UNKNOWN;
    }
}