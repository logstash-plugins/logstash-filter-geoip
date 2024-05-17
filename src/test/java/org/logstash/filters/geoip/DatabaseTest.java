package org.logstash.filters.geoip;

import com.maxmind.geoip2.DatabaseReader;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.io.IOException;
import java.nio.file.Path;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DatabaseTest {

    private static final Map<Database, List<Path>> DATABASES_TO_MAXMIND_FILES = Map.of(
            Database.CITY, List.of(MaxMindDatabases.GEOIP2_CITY, MaxMindDatabases.GEOLITE2_CITY),
            Database.COUNTRY, List.of(MaxMindDatabases.GEOIP2_COUNTRY, MaxMindDatabases.GEOLITE2_COUNTRY),
            Database.DOMAIN, List.of(MaxMindDatabases.GEOIP2_DOMAIN),
            Database.ASN, List.of(MaxMindDatabases.GEOLITE2_ASN),
            Database.ANONYMOUS_IP, List.of(MaxMindDatabases.GEOIP2_ANONYMOUS_IP),
            Database.ISP, List.of(MaxMindDatabases.GEOIP2_ISP),
            Database.ENTERPRISE, List.of(MaxMindDatabases.GEOIP2_ENTERPRISE),
            Database.UNKNOWN, List.of()
    );

    @Test
    void testCityDefaultFields() {
        final EnumSet<Field> expectedFields = EnumSet.of(
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
                Field.LONGITUDE
        );

        assertEquals(expectedFields, Database.CITY.getDefaultFields());
    }

    @Test
    void testCountryDefaultFields() {
        final EnumSet<Field> expectedFields = EnumSet.of(
                Field.IP,
                Field.COUNTRY_CODE2,
                Field.COUNTRY_NAME,
                Field.CONTINENT_NAME
        );

        assertEquals(expectedFields, Database.COUNTRY.getDefaultFields());
    }

    @Test
    void testDomainDefaultFields() {
        final EnumSet<Field> expectedFields = EnumSet.of(Field.DOMAIN);

        assertEquals(expectedFields, Database.DOMAIN.getDefaultFields());
    }

    @Test
    void testAsnDefaultFields() {
        final EnumSet<Field> expectedFields = EnumSet.of(
                Field.IP,
                Field.AUTONOMOUS_SYSTEM_NUMBER,
                Field.AUTONOMOUS_SYSTEM_ORGANIZATION
        );

        assertEquals(expectedFields, Database.ASN.getDefaultFields());
    }

    @Test
    void testIspDefaultFields() {
        final EnumSet<Field> expectedFields = EnumSet.of(
                Field.IP,
                Field.AUTONOMOUS_SYSTEM_NUMBER,
                Field.AUTONOMOUS_SYSTEM_ORGANIZATION,
                Field.ISP,
                Field.ORGANIZATION
        );

        assertEquals(expectedFields, Database.ISP.getDefaultFields());
    }

    @Test
    void testAnonymousIpDefaultFields() {
        final EnumSet<Field> expectedFields = EnumSet.of(
                Field.HOSTING_PROVIDER,
                Field.TOR_EXIT_NODE,
                Field.ANONYMOUS_VPN,
                Field.ANONYMOUS,
                Field.PUBLIC_PROXY,
                Field.RESIDENTIAL_PROXY
        );

        assertEquals(expectedFields, Database.ANONYMOUS_IP.getDefaultFields());
    }

    @Test
    void testEnterpriseDefaultFields() {
        final EnumSet<Field> expectedFields = EnumSet.of(
                Field.IP,
                Field.COUNTRY_CODE2,
                Field.COUNTRY_NAME,
                Field.CONTINENT_NAME,
                Field.REGION_ISO_CODE,
                Field.REGION_NAME,
                Field.CITY_NAME,
                Field.LOCATION
        );

        assertEquals(expectedFields, Database.ENTERPRISE.getDefaultFields());
    }

    @ParameterizedTest
    @EnumSource(Database.class)
    void fromDatabaseTypeWithMaxMindFilesShouldReturnDatabase(Database expectedDatabase) throws IOException {
        for (final Path path : DATABASES_TO_MAXMIND_FILES.get(expectedDatabase)) {
            try (final DatabaseReader reader = new DatabaseReader
                    .Builder(path.toFile())
                    .build()) {

                final String fileDatabaseType = reader.getMetadata().getDatabaseType();
                final Database parseDatabase = Database.fromDatabaseType(fileDatabaseType);
                final String message = String.format("File '%s' was parsed as %s database instead of %s", path, parseDatabase, expectedDatabase);

                assertEquals(expectedDatabase, parseDatabase, message);
            }
        }
    }

    @Test
    void fromDatabaseTypeWithKnownDatabaseTypesShouldReturnDatabase() {
        assertEquals(Database.CITY, Database.fromDatabaseType("GeoLite2-City"));
        assertEquals(Database.CITY, Database.fromDatabaseType("GeoIP2-City"));
        assertEquals(Database.CITY, Database.fromDatabaseType("GeoIP2-City-Africa"));
        assertEquals(Database.CITY, Database.fromDatabaseType("GeoIP2-City-Asia-Pacific"));
        assertEquals(Database.CITY, Database.fromDatabaseType("GeoIP2-City-Europe"));
        assertEquals(Database.CITY, Database.fromDatabaseType("GeoIP2-City-North-America"));
        assertEquals(Database.CITY, Database.fromDatabaseType("GeoIP2-City-South-America"));
        assertEquals(Database.COUNTRY, Database.fromDatabaseType("GeoLite2-Country"));
        assertEquals(Database.COUNTRY, Database.fromDatabaseType("GeoIP2-Country"));
        assertEquals(Database.DOMAIN, Database.fromDatabaseType("GeoIP2-Domain"));
        assertEquals(Database.ASN, Database.fromDatabaseType("GeoLite2-ASN"));
        assertEquals(Database.ISP, Database.fromDatabaseType("GeoIP2-ISP"));
        assertEquals(Database.ANONYMOUS_IP, Database.fromDatabaseType("GeoIP2-Anonymous-IP"));
        assertEquals(Database.ENTERPRISE, Database.fromDatabaseType("Enterprise"));
    }
}