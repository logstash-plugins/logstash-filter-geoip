package org.logstash.filters.geoip;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FieldsTest {

    @ParameterizedTest
    @EnumSource(Fields.class)
    void parseFieldWithValidFieldNameShouldReturnField(Fields field) {
        final String lowerCaseFieldName = field.name().toLowerCase();
        assertEquals(field, Fields.parseField(lowerCaseFieldName));
    }

    @Test
    void parseFieldWithInvalidFieldNameShouldThrown() {
        final IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> Fields.parseField("foobar"));
        assertTrue(thrown.getMessage().startsWith("illegal field value foobar. valid values are"));
    }

    @Test
    void testFieldNames() {
        assertFieldNames(Fields.AUTONOMOUS_SYSTEM_NUMBER, "as.number", "asn");
        assertFieldNames(Fields.AUTONOMOUS_SYSTEM_ORGANIZATION, "as.organization.name", "as_org");
        assertFieldNames(Fields.CITY_NAME, "geo.city_name", "city_name");
        assertFieldNames(Fields.COUNTRY_NAME, "geo.country_name", "country_name");
        assertFieldNames(Fields.CONTINENT_CODE, "geo.continent_code", "continent_code");
        assertFieldNames(Fields.CONTINENT_NAME, "geo.continent_name", "continent_name");
        assertFieldNames(Fields.COUNTRY_CODE2, "geo.country_iso_code", "country_code2");
        assertFieldNames(Fields.COUNTRY_CODE3, "", "country_code3");
        assertFieldNames(Fields.DOMAIN, "domain", "domain");
        assertFieldNames(Fields.IP, "ip", "ip");
        assertFieldNames(Fields.ISP, "mmdb.isp", "isp");
        assertFieldNames(Fields.POSTAL_CODE, "geo.postal_code", "postal_code");
        assertFieldNames(Fields.DMA_CODE, "mmdb.dma_code", "dma_code");
        assertFieldNames(Fields.REGION_NAME, "geo.region_name", "region_name");
        assertFieldNames(Fields.REGION_CODE, "geo.region_code", "region_code");
        assertFieldNames(Fields.REGION_ISO_CODE, "geo.region_iso_code", "region_iso_code");
        assertFieldNames(Fields.TIMEZONE, "geo.timezone", "timezone");
        assertFieldNames(Fields.LOCATION, "geo.location", "location");
        assertFieldNames(Fields.LATITUDE, "geo.location.lat", "latitude");
        assertFieldNames(Fields.LONGITUDE, "geo.location.lon", "longitude");
        assertFieldNames(Fields.ORGANIZATION, "mmdb.organization", "organization");
        assertFieldNames(Fields.NETWORK, "traits.network", "network");
        assertFieldNames(Fields.HOSTING_PROVIDER, "traits.hosting_provider", "hosting_provider");
        assertFieldNames(Fields.TOR_EXIT_NODE, "traits.tor_exit_node", "tor_exit_node");
        assertFieldNames(Fields.ANONYMOUS_VPN, "traits.anonymous_vpn", "anonymous_vpn");
        assertFieldNames(Fields.ANONYMOUS, "traits.anonymous", "anonymous");
        assertFieldNames(Fields.PUBLIC_PROXY, "traits.public_proxy", "public_proxy");
        assertFieldNames(Fields.RESIDENTIAL_PROXY, "traits.residential_proxy", "residential_proxy");
    }

    void assertFieldNames(Fields field, String expectedEcsFieldName, String expectedFieldName) {
        assertEquals(expectedEcsFieldName, field.getEcsFieldName());
        assertEquals(Fields.normalizeFieldReferenceFragment(expectedEcsFieldName), field.getFieldReferenceECSv1());

        assertEquals(expectedFieldName, field.fieldName());
        assertEquals(Fields.normalizeFieldReferenceFragment(expectedFieldName), field.getFieldReferenceLegacy());
    }
}