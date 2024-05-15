package org.logstash.filters.geoip;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.logstash.Event;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.logstash.ext.JrubyEventExtLibrary.RubyEvent;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


class GeoIPFilterTest {

    private static final String SOURCE_FIELD = "ip";
    private static final String TARGET_FIELD = "data";

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void handleEventWithGeoIp2CityDatabaseShouldProperlyCreateEvent(boolean ecsEnabled) {
        final List<Fields> supportedFields = List.of(
                Fields.IP,
                Fields.CITY_NAME,
                Fields.CONTINENT_CODE,
                Fields.CONTINENT_NAME,
                Fields.COUNTRY_NAME,
                Fields.COUNTRY_CODE2,
                Fields.COUNTRY_CODE3,
                Fields.POSTAL_CODE,
                Fields.DMA_CODE,
                Fields.REGION_NAME,
                Fields.REGION_CODE,
                Fields.REGION_ISO_CODE,
                Fields.TIMEZONE,
                Fields.LOCATION,
                Fields.LATITUDE,
                Fields.LONGITUDE
        );

        try (final GeoIPFilter filter = createFilter(MaxMindDatabases.GEOIP2_CITY, ecsEnabled, supportedFields)) {
            final RubyEvent rubyEvent = mockRubyEvent("216.160.83.58");
            assertTrue(filter.handleEvent(rubyEvent));

            final Event event = rubyEvent.getEvent();
            assertEquals("216.160.83.58", getField(event, Fields.IP, ecsEnabled));
            assertEquals("Milton", getField(event, Fields.CITY_NAME, ecsEnabled));
            assertEquals("NA", getField(event, Fields.CONTINENT_CODE, ecsEnabled));
            assertEquals("North America", getField(event, Fields.CONTINENT_NAME, ecsEnabled));
            assertEquals("United States", getField(event, Fields.COUNTRY_NAME, ecsEnabled));
            assertEquals("US", getField(event, Fields.COUNTRY_CODE2, ecsEnabled));
            assertEquals("98354", getField(event, Fields.POSTAL_CODE, ecsEnabled));
            assertEquals(819L, getField(event, Fields.DMA_CODE, ecsEnabled));
            assertEquals("Washington", getField(event, Fields.REGION_NAME, ecsEnabled));
            assertEquals("WA", getField(event, Fields.REGION_CODE, ecsEnabled));
            assertEquals("US-WA", getField(event, Fields.REGION_ISO_CODE, ecsEnabled));
            assertEquals("America/Los_Angeles", getField(event, Fields.TIMEZONE, ecsEnabled));
            assertEquals(Map.of("lat", 47.2513, "lon", -122.3149), getField(event, Fields.LOCATION, ecsEnabled));
            assertEquals(47.2513, getField(event, Fields.LATITUDE, ecsEnabled));
            assertEquals(-122.3149, getField(event, Fields.LONGITUDE, ecsEnabled));

            if (!ecsEnabled) {
                assertEquals("US", getField(event, Fields.COUNTRY_CODE3, false));
            }
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void handleEventWithNoCustomFieldsShouldProperlyAddCityFields(boolean ecsEnabled) {
        try (final GeoIPFilter filter = createFilter(MaxMindDatabases.GEOIP2_CITY, ecsEnabled, List.of())) {
            final RubyEvent rubyEvent = mockRubyEvent("216.160.83.58");
            assertTrue(filter.handleEvent(rubyEvent));

            final Event event = rubyEvent.getEvent();
            assertEquals(ecsEnabled, event.includes(getFieldReference(Fields.REGION_ISO_CODE, ecsEnabled)));
            assertEquals(!ecsEnabled, event.includes(getFieldReference(Fields.REGION_CODE, ecsEnabled)));
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void handleEventWithGeoIp2CountryDatabaseShouldProperlyCreateEvent(boolean ecsEnabled) {
        final List<Fields> supportedFields = List.of(
                Fields.IP,
                Fields.COUNTRY_CODE2,
                Fields.COUNTRY_NAME,
                Fields.CONTINENT_NAME
        );

        try (final GeoIPFilter filter = createFilter(MaxMindDatabases.GEOIP2_COUNTRY, ecsEnabled, supportedFields)) {
            final RubyEvent rubyEvent = mockRubyEvent("2a02:d5c0:0:0:0:0:0:0");
            assertTrue(filter.handleEvent(rubyEvent));

            final Event event = rubyEvent.getEvent();
            assertEquals("2a02:d5c0:0:0:0:0:0:0", getField(event, Fields.IP, ecsEnabled));
            assertEquals("ES", getField(event, Fields.COUNTRY_CODE2, ecsEnabled));
            assertEquals("Spain", getField(event, Fields.COUNTRY_NAME, ecsEnabled));
            assertEquals("Europe", getField(event, Fields.CONTINENT_NAME, ecsEnabled));
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void handleEventWithGeoIp2IspDatabaseShouldProperlyCreateEvent(boolean ecsEnabled) {
        final List<Fields> supportedFields = List.of(
                Fields.IP,
                Fields.AUTONOMOUS_SYSTEM_NUMBER,
                Fields.AUTONOMOUS_SYSTEM_ORGANIZATION,
                Fields.ISP,
                Fields.ORGANIZATION
        );

        try (final GeoIPFilter filter = createFilter(MaxMindDatabases.GEOIP2_ISP, ecsEnabled, supportedFields)) {
            final RubyEvent rubyEvent = mockRubyEvent("1.128.0.1");
            assertTrue(filter.handleEvent(rubyEvent));

            final Event event = rubyEvent.getEvent();
            assertEquals("1.128.0.1", getField(event, Fields.IP, ecsEnabled));
            assertEquals(1221L, getField(event, Fields.AUTONOMOUS_SYSTEM_NUMBER, ecsEnabled));
            assertEquals("Telstra Pty Ltd", getField(event, Fields.AUTONOMOUS_SYSTEM_ORGANIZATION, ecsEnabled));
            assertEquals("Telstra Internet", getField(event, Fields.ISP, ecsEnabled));
            assertEquals("Telstra Internet", getField(event, Fields.ORGANIZATION, ecsEnabled));
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void handleEventWithGeoLite2AsnDatabaseShouldProperlyCreateEvent(boolean ecsEnabled) {
        final List<Fields> supportedFields = List.of(
                Fields.IP,
                Fields.AUTONOMOUS_SYSTEM_NUMBER,
                Fields.AUTONOMOUS_SYSTEM_ORGANIZATION,
                Fields.NETWORK
        );

        try (final GeoIPFilter filter = createFilter(MaxMindDatabases.GEOLITE2_ASN, ecsEnabled, supportedFields)) {
            final RubyEvent rubyEvent = mockRubyEvent("12.81.92.1");
            assertTrue(filter.handleEvent(rubyEvent));

            final Event event = rubyEvent.getEvent();
            assertEquals("12.81.92.1", getField(event, Fields.IP, ecsEnabled));
            assertEquals(7018L, getField(event, Fields.AUTONOMOUS_SYSTEM_NUMBER, ecsEnabled));
            assertEquals("AT&T Services", getField(event, Fields.AUTONOMOUS_SYSTEM_ORGANIZATION, ecsEnabled));
            assertEquals("12.81.92.0/22", getField(event, Fields.NETWORK, ecsEnabled));
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void handleEventWithGeoIp2DomainDatabaseShouldProperlyCreateEvent(boolean ecsEnabled) {
        final List<Fields> supportedFields = List.of(Fields.DOMAIN);
        try (final GeoIPFilter filter = createFilter(MaxMindDatabases.GEOIP2_DOMAIN, ecsEnabled, supportedFields)) {
            final RubyEvent rubyEvent = mockRubyEvent("1.2.0.1");
            assertTrue(filter.handleEvent(rubyEvent));

            final Event event = rubyEvent.getEvent();
            assertEquals("maxmind.com", getField(event, Fields.DOMAIN, ecsEnabled));
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void handleEventWithGeoIp2EnterpriseDatabaseShouldProperlyCreateEvent(boolean ecsEnabled) {
        final List<Fields> supportedFields = List.of(
                Fields.IP,
                Fields.COUNTRY_CODE2,
                Fields.COUNTRY_NAME,
                Fields.CONTINENT_NAME,
                Fields.REGION_ISO_CODE,
                Fields.REGION_NAME,
                Fields.CITY_NAME,
                Fields.TIMEZONE,
                Fields.LOCATION,
                Fields.AUTONOMOUS_SYSTEM_NUMBER,
                Fields.AUTONOMOUS_SYSTEM_ORGANIZATION,
                Fields.NETWORK,
                Fields.HOSTING_PROVIDER,
                Fields.TOR_EXIT_NODE,
                Fields.ANONYMOUS_VPN,
                Fields.ANONYMOUS,
                Fields.PUBLIC_PROXY,
                Fields.RESIDENTIAL_PROXY
        );

        try (final GeoIPFilter filter = createFilter(MaxMindDatabases.GEOIP2_ENTERPRISE, ecsEnabled, supportedFields)) {
            final RubyEvent rubyEvent = mockRubyEvent("74.209.24.1");
            assertTrue(filter.handleEvent(rubyEvent));

            final Event event = rubyEvent.getEvent();
            assertEquals("74.209.24.1", getField(event, Fields.IP, ecsEnabled));
            assertEquals("US", getField(event, Fields.COUNTRY_CODE2, ecsEnabled));
            assertEquals("United States", getField(event, Fields.COUNTRY_NAME, ecsEnabled));
            assertEquals("North America", getField(event, Fields.CONTINENT_NAME, ecsEnabled));
            assertEquals("US-NY", getField(event, Fields.REGION_ISO_CODE, ecsEnabled));
            assertEquals("New York", getField(event, Fields.REGION_NAME, ecsEnabled));
            assertEquals("Chatham", getField(event, Fields.CITY_NAME, ecsEnabled));
            assertEquals("America/New_York", getField(event, Fields.TIMEZONE, ecsEnabled));
            assertEquals(Map.of("lat", 42.3478, "lon", -73.5549), getField(event, Fields.LOCATION, ecsEnabled));
            assertEquals(14671L, getField(event, Fields.AUTONOMOUS_SYSTEM_NUMBER, ecsEnabled));
            assertEquals("FairPoint Communications", getField(event, Fields.AUTONOMOUS_SYSTEM_ORGANIZATION, ecsEnabled));
            assertEquals("74.209.16.0/20", getField(event, Fields.NETWORK, ecsEnabled));
            assertEquals(false, getField(event, Fields.HOSTING_PROVIDER, ecsEnabled));
            assertEquals(false, getField(event, Fields.TOR_EXIT_NODE, ecsEnabled));
            assertEquals(false, getField(event, Fields.ANONYMOUS_VPN, ecsEnabled));
            assertEquals(false, getField(event, Fields.ANONYMOUS, ecsEnabled));
            assertEquals(false, getField(event, Fields.PUBLIC_PROXY, ecsEnabled));
            assertEquals(false, getField(event, Fields.RESIDENTIAL_PROXY, ecsEnabled));
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void handleEventWithGeoIp2AnonymousIpDatabaseShouldProperlyCreateEvent(boolean ecsEnabled) {
        final List<Fields> supportedFields = List.of(
                Fields.IP,
                Fields.HOSTING_PROVIDER,
                Fields.TOR_EXIT_NODE,
                Fields.ANONYMOUS_VPN,
                Fields.ANONYMOUS,
                Fields.PUBLIC_PROXY,
                Fields.RESIDENTIAL_PROXY
        );

        try (final GeoIPFilter filter = createFilter(MaxMindDatabases.GEOIP2_ANONYMOUS_IP, ecsEnabled, supportedFields)) {
            final RubyEvent rubyEvent = mockRubyEvent("81.2.69.1");
            assertTrue(filter.handleEvent(rubyEvent));

            final Event event = rubyEvent.getEvent();
            assertEquals("81.2.69.1", getField(event, Fields.IP, ecsEnabled));
            assertEquals(true, getField(event, Fields.HOSTING_PROVIDER, ecsEnabled));
            assertEquals(true, getField(event, Fields.TOR_EXIT_NODE, ecsEnabled));
            assertEquals(true, getField(event, Fields.ANONYMOUS_VPN, ecsEnabled));
            assertEquals(true, getField(event, Fields.ANONYMOUS, ecsEnabled));
            assertEquals(true, getField(event, Fields.PUBLIC_PROXY, ecsEnabled));
            assertEquals(true, getField(event, Fields.RESIDENTIAL_PROXY, ecsEnabled));
        }
    }

    @Test
    void handleEventWithNoCustomFieldsShouldUseDatabasesDefaultFields() {
        try (final GeoIPFilter filter = createFilter(MaxMindDatabases.GEOIP2_COUNTRY, true, List.of())) {
            final RubyEvent rubyEvent = mockRubyEvent("216.160.83.58");
            assertTrue(filter.handleEvent(rubyEvent));

            final Event event = rubyEvent.getEvent();
            for (final Fields defaultField : Databases.COUNTRY.getDefaultFields()) {
                final String fieldReference = getFieldReference(defaultField, true);

                assertTrue(event.includes(fieldReference), () -> String.format(
                        "Default field %s (Fields.%s) not found on the Logstash event: %s",
                        fieldReference,
                        defaultField,
                        event.toMap()
                ));
            }
        }
    }

    @Test
    void handleEventWithListSourceFieldShouldParseFirstIp() {
        try (final GeoIPFilter filter = createFilter(MaxMindDatabases.GEOIP2_COUNTRY, true, List.of())) {
            final RubyEvent rubyEvent = mockRubyEvent(new Event(Map.of(SOURCE_FIELD, List.of("216.160.83.58", "127.0.0.1"))));

            assertTrue(filter.handleEvent(rubyEvent));

            final Event event = rubyEvent.getEvent();
            assertEquals("216.160.83.58", getField(event, Fields.IP, true));
        }
    }

    private Object getField(Event event, Fields field, boolean ecsEnabled) {
        return event.getField(getFieldReference(field, ecsEnabled));
    }

    private String getFieldReference(Fields field, boolean ecsEnabled) {
        final String fieldReference = (ecsEnabled ? field.getFieldReferenceECSv1() : field.getFieldReferenceLegacy());
        return String.format("[%s]%s", TARGET_FIELD, fieldReference);
    }

    private RubyEvent mockRubyEvent(String ipAddress) {
        return mockRubyEvent(new Event(Map.of(SOURCE_FIELD, ipAddress)));
    }

    private RubyEvent mockRubyEvent(Event event) {
        final RubyEvent rubyEvent = mock(RubyEvent.class);
        when(rubyEvent.getEvent()).thenReturn(event);
        return rubyEvent;
    }

    private GeoIPFilter createFilter(Path databasePath, boolean ecsEnabled, List<Fields> fields) {
        return new GeoIPFilter(
                SOURCE_FIELD,
                TARGET_FIELD,
                fields.stream().map(Enum::name).collect(Collectors.toList()),
                databasePath.toString(),
                1000,
                (ecsEnabled ? "v1" : "disabled")
        );
    }
}