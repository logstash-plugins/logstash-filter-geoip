package org.logstash.filters.geoip;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FieldTest {

    @ParameterizedTest
    @EnumSource(Field.class)
    void parseFieldWithValidFieldNameShouldReturnField(Field field) {
        final String lowerCaseFieldName = field.name().toLowerCase();
        assertEquals(field, Field.parseField(lowerCaseFieldName));
    }

    @Test
    void parseFieldWithInvalidFieldNameShouldThrown() {
        final IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> Field.parseField("foobar"));
        assertTrue(thrown.getMessage().startsWith("illegal field value foobar. valid values are"));
    }

    @Test
    void testFieldNames() {
        assertFieldNames(Field.AUTONOMOUS_SYSTEM_NUMBER, "as.number", "asn");
        assertFieldNames(Field.AUTONOMOUS_SYSTEM_ORGANIZATION, "as.organization.name", "as_org");
        assertFieldNames(Field.CITY_NAME, "geo.city_name", "city_name");
        assertFieldNames(Field.COUNTRY_NAME, "geo.country_name", "country_name");
        assertFieldNames(Field.CONTINENT_CODE, "geo.continent_code", "continent_code");
        assertFieldNames(Field.CONTINENT_NAME, "geo.continent_name", "continent_name");
        assertFieldNames(Field.COUNTRY_CODE2, "geo.country_iso_code", "country_code2");
        assertFieldNames(Field.COUNTRY_CODE3, "", "country_code3");
        assertFieldNames(Field.DOMAIN, "domain", "domain");
        assertFieldNames(Field.IP, "ip", "ip");
        assertFieldNames(Field.ISP, "mmdb.isp", "isp");
        assertFieldNames(Field.POSTAL_CODE, "geo.postal_code", "postal_code");
        assertFieldNames(Field.DMA_CODE, "mmdb.dma_code", "dma_code");
        assertFieldNames(Field.REGION_NAME, "geo.region_name", "region_name");
        assertFieldNames(Field.REGION_CODE, "geo.region_code", "region_code");
        assertFieldNames(Field.REGION_ISO_CODE, "geo.region_iso_code", "region_iso_code");
        assertFieldNames(Field.TIMEZONE, "geo.timezone", "timezone");
        assertFieldNames(Field.LOCATION, "geo.location", "location");
        assertFieldNames(Field.LATITUDE, "geo.location.lat", "latitude");
        assertFieldNames(Field.LONGITUDE, "geo.location.lon", "longitude");
        assertFieldNames(Field.ORGANIZATION, "mmdb.organization", "organization");
        assertFieldNames(Field.NETWORK, "ip_traits.network", "network");
        assertFieldNames(Field.HOSTING_PROVIDER, "ip_traits.hosting_provider", "hosting_provider");
        assertFieldNames(Field.TOR_EXIT_NODE, "ip_traits.tor_exit_node", "tor_exit_node");
        assertFieldNames(Field.ANONYMOUS_VPN, "ip_traits.anonymous_vpn", "anonymous_vpn");
        assertFieldNames(Field.ANONYMOUS, "ip_traits.anonymous", "anonymous");
        assertFieldNames(Field.PUBLIC_PROXY, "ip_traits.public_proxy", "public_proxy");
        assertFieldNames(Field.RESIDENTIAL_PROXY, "ip_traits.residential_proxy", "residential_proxy");
    }

    void assertFieldNames(Field field, String expectedEcsFieldName, String expectedFieldName) {
        assertEquals(expectedEcsFieldName, field.getEcsFieldName());
        assertEquals(Field.normalizeFieldReferenceFragment(expectedEcsFieldName), field.getFieldReferenceECSv1());

        assertEquals(expectedFieldName, field.fieldName());
        assertEquals(Field.normalizeFieldReferenceFragment(expectedFieldName), field.getFieldReferenceLegacy());
    }
}