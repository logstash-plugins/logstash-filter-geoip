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

class DatabasesTest {

    private static final Map<Databases, List<Path>> DATABASES_TO_MAXMIND_FILES = Map.of(
            Databases.CITY, List.of(MaxMindDatabases.GEOIP2_CITY, MaxMindDatabases.GEOLITE2_CITY),
            Databases.COUNTRY, List.of(MaxMindDatabases.GEOIP2_COUNTRY, MaxMindDatabases.GEOLITE2_COUNTRY),
            Databases.DOMAIN, List.of(MaxMindDatabases.GEOIP2_DOMAIN),
            Databases.ASN, List.of(MaxMindDatabases.GEOLITE2_ASN),
            Databases.ANONYMOUS_IP, List.of(MaxMindDatabases.GEOIP2_ANONYMOUS_IP),
            Databases.ISP, List.of(MaxMindDatabases.GEOIP2_ISP),
            Databases.ENTERPRISE, List.of(MaxMindDatabases.GEOIP2_ENTERPRISE),
            Databases.UNKNOWN, List.of()
    );

    @Test
    void testCityDefaultFields() {
        final EnumSet<Fields> expectedFields = EnumSet.of(
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
        );

        assertEquals(expectedFields, Databases.CITY.getDefaultFields());
    }

    @Test
    void testCountryDefaultFields() {
        final EnumSet<Fields> expectedFields = EnumSet.of(
                Fields.IP,
                Fields.COUNTRY_CODE2,
                Fields.COUNTRY_NAME,
                Fields.CONTINENT_NAME
        );

        assertEquals(expectedFields, Databases.COUNTRY.getDefaultFields());
    }

    @Test
    void testDomainDefaultFields() {
        final EnumSet<Fields> expectedFields = EnumSet.of(Fields.DOMAIN);

        assertEquals(expectedFields, Databases.DOMAIN.getDefaultFields());
    }

    @Test
    void testAsnDefaultFields() {
        final EnumSet<Fields> expectedFields = EnumSet.of(
                Fields.IP,
                Fields.AUTONOMOUS_SYSTEM_NUMBER,
                Fields.AUTONOMOUS_SYSTEM_ORGANIZATION
        );

        assertEquals(expectedFields, Databases.ASN.getDefaultFields());
    }

    @Test
    void testIspDefaultFields() {
        final EnumSet<Fields> expectedFields = EnumSet.of(
                Fields.IP,
                Fields.AUTONOMOUS_SYSTEM_NUMBER,
                Fields.AUTONOMOUS_SYSTEM_ORGANIZATION,
                Fields.ISP,
                Fields.ORGANIZATION
        );

        assertEquals(expectedFields, Databases.ISP.getDefaultFields());
    }

    @Test
    void testAnonymousIpDefaultFields() {
        final EnumSet<Fields> expectedFields = EnumSet.of(
                Fields.HOSTING_PROVIDER,
                Fields.TOR_EXIT_NODE,
                Fields.ANONYMOUS_VPN,
                Fields.ANONYMOUS,
                Fields.PUBLIC_PROXY,
                Fields.RESIDENTIAL_PROXY
        );

        assertEquals(expectedFields, Databases.ANONYMOUS_IP.getDefaultFields());
    }

    @Test
    void testEnterpriseDefaultFields() {
        final EnumSet<Fields> expectedFields = EnumSet.of(
                Fields.IP,
                Fields.COUNTRY_CODE2,
                Fields.COUNTRY_NAME,
                Fields.CONTINENT_NAME,
                Fields.REGION_ISO_CODE,
                Fields.REGION_NAME,
                Fields.CITY_NAME,
                Fields.LOCATION
        );

        assertEquals(expectedFields, Databases.ENTERPRISE.getDefaultFields());
    }

    @ParameterizedTest
    @EnumSource(Databases.class)
    void fromDatabaseTypeWithMaxMindFilesShouldReturnDatabase(Databases expectedDatabase) throws IOException {
        for (final Path path : DATABASES_TO_MAXMIND_FILES.get(expectedDatabase)) {
            try (final DatabaseReader reader = new DatabaseReader
                    .Builder(path.toFile())
                    .build()) {

                final String fileDatabaseType = reader.getMetadata().getDatabaseType();
                final Databases parseDatabase = Databases.fromDatabaseType(fileDatabaseType);
                final String message = String.format("File '%s' was parsed as %s database instead of %s", path, parseDatabase, expectedDatabase);

                assertEquals(expectedDatabase, parseDatabase, message);
            }
        }
    }

    @Test
    void fromDatabaseTypeWithKnownDatabaseTypesShouldReturnDatabase() {
        assertEquals(Databases.CITY, Databases.fromDatabaseType("GeoLite2-City"));
        assertEquals(Databases.CITY, Databases.fromDatabaseType("GeoIP2-City"));
        assertEquals(Databases.CITY, Databases.fromDatabaseType("GeoIP2-City-Africa"));
        assertEquals(Databases.CITY, Databases.fromDatabaseType("GeoIP2-City-Asia-Pacific"));
        assertEquals(Databases.CITY, Databases.fromDatabaseType("GeoIP2-City-Europe"));
        assertEquals(Databases.CITY, Databases.fromDatabaseType("GeoIP2-City-North-America"));
        assertEquals(Databases.CITY, Databases.fromDatabaseType("GeoIP2-City-South-America"));
        assertEquals(Databases.COUNTRY, Databases.fromDatabaseType("GeoLite2-Country"));
        assertEquals(Databases.COUNTRY, Databases.fromDatabaseType("GeoIP2-Country"));
        assertEquals(Databases.DOMAIN, Databases.fromDatabaseType("GeoIP2-Domain"));
        assertEquals(Databases.ASN, Databases.fromDatabaseType("GeoLite2-ASN"));
        assertEquals(Databases.ISP, Databases.fromDatabaseType("GeoIP2-ISP"));
        assertEquals(Databases.ANONYMOUS_IP, Databases.fromDatabaseType("GeoIP2-Anonymous-IP"));
        assertEquals(Databases.ENTERPRISE, Databases.fromDatabaseType("Enterprise"));
    }
}