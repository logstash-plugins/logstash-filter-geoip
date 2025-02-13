package org.logstash.filters.geoip;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

enum Database {

    CITY(
            "City",
            EnumSet.of(
                    Field.IP,
                    Field.CITY_NAME,
                    Field.CONTINENT_CODE,
                    Field.COUNTRY_NAME,
                    Field.COUNTRY_CODE2,
                    Field.COUNTRY_CODE3,
                    Field.POSTAL_CODE,
                    Field.DMA_CODE,
                    Field.REGION_NAME,
                    Field.REGION_ISO_CODE,
                    Field.TIMEZONE,
                    Field.LOCATION,
                    Field.LATITUDE,
                    Field.LONGITUDE,
                    Field.NETWORK
            )
    ),
    COUNTRY(
            "Country",
            EnumSet.of(
                    Field.IP,
                    Field.COUNTRY_CODE2,
                    Field.COUNTRY_NAME,
                    Field.CONTINENT_NAME,
                    Field.NETWORK
            )
    ),
    DOMAIN(
            "GeoIP2-Domain",
            EnumSet.of(
                    Field.DOMAIN
            )
    ),
    ASN(
            "GeoLite2-ASN",
            EnumSet.of(
                    Field.IP,
                    Field.AUTONOMOUS_SYSTEM_NUMBER,
                    Field.AUTONOMOUS_SYSTEM_ORGANIZATION
            )
    ),
    ISP(
            "GeoIP2-ISP",
            EnumSet.of(
                    Field.IP,
                    Field.AUTONOMOUS_SYSTEM_NUMBER,
                    Field.AUTONOMOUS_SYSTEM_ORGANIZATION,
                    Field.ISP,
                    Field.ORGANIZATION,
                    Field.NETWORK
            )
    ),
    ANONYMOUS_IP(
            "GeoIP2-Anonymous-IP",
            EnumSet.of(
                    Field.HOSTING_PROVIDER,
                    Field.TOR_EXIT_NODE,
                    Field.ANONYMOUS_VPN,
                    Field.ANONYMOUS,
                    Field.PUBLIC_PROXY,
                    Field.RESIDENTIAL_PROXY,
                    Field.NETWORK
            )
    ),
    ENTERPRISE(
            "Enterprise",
            EnumSet.of(
                    Field.IP,
                    Field.COUNTRY_CODE2,
                    Field.COUNTRY_NAME,
                    Field.CONTINENT_NAME,
                    Field.REGION_ISO_CODE,
                    Field.REGION_NAME,
                    Field.CITY_NAME,
                    Field.LOCATION
            )
    ),
    UNKNOWN(
            "Unknown",
            EnumSet.noneOf(Field.class)
    );

    private final String databaseType;
    private final Set<Field> defaultFields;

    Database(String databaseType, final Set<Field> defaultFields) {
        this.databaseType = databaseType;
        this.defaultFields = defaultFields;
    }

    public Set<Field> getDefaultFields() {
        return Collections.unmodifiableSet(defaultFields);
    }

    public static Database fromDatabaseType(final String type) {
        // It follows the same com.maxmind.geoip2.DatabaseReader#getDatabaseType logic
        if (type.contains(CITY.databaseType)) {
            return Database.CITY;
        } else if (type.contains(COUNTRY.databaseType)) {
            return Database.COUNTRY;
        } else if (type.contains(DOMAIN.databaseType)) {
            return Database.DOMAIN;
        } else if (type.contains(ASN.databaseType)) {
            return Database.ASN;
        } else if (type.contains(ISP.databaseType)) {
            return Database.ISP;
        } else if (type.contains(ENTERPRISE.databaseType)) {
            return Database.ENTERPRISE;
        } else if (type.contains(ANONYMOUS_IP.databaseType)) {
            return Database.ANONYMOUS_IP;
        }

        // The reason why we have this UNKNOWN type here, is to keep it backward compatible,
        // allowing the pipeline to start, even if the plugin is configured to a non supported
        // database type.
        return Database.UNKNOWN;
    }
}
