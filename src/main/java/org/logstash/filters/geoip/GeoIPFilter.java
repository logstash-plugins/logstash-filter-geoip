/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.logstash.filters.geoip;

import com.maxmind.db.CHMCache;
import com.maxmind.db.InvalidDatabaseException;
import com.maxmind.db.Network;
import com.maxmind.geoip2.exception.AddressNotFoundException;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.AnonymousIpResponse;
import com.maxmind.geoip2.model.AsnResponse;
import com.maxmind.geoip2.model.CityResponse;
import com.maxmind.geoip2.model.CountryResponse;
import com.maxmind.geoip2.model.DomainResponse;
import com.maxmind.geoip2.model.EnterpriseResponse;
import com.maxmind.geoip2.model.IspResponse;
import com.maxmind.geoip2.record.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.logstash.Event;

import com.maxmind.geoip2.DatabaseReader;
import org.logstash.ext.JrubyEventExtLibrary.RubyEvent;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

public class GeoIPFilter implements Closeable {
  private static final Logger logger = LogManager.getLogger();
  private final String sourceField;
  private final String targetField;
  private final Set<Fields> desiredFields;
  private final Databases database;
  private final DatabaseReader databaseReader;
  private final Function<Fields,String> fieldReferenceExtractor;

  public GeoIPFilter(String sourceField, String targetField, List<String> fields, String databasePath, int cacheSize,
                     String ecsCompatibility) {
    this.sourceField = sourceField;
    this.targetField = targetField;
    switch (ecsCompatibility) {
      case "disabled":
        this.fieldReferenceExtractor = Fields::getFieldReferenceLegacy;
        break;
      case "v1":
      case "v8":
        this.fieldReferenceExtractor = Fields::getFieldReferenceECSv1;
        break;
      default:
        throw new UnsupportedOperationException("Unknown ECS version " + ecsCompatibility);
    }

    final File databaseFile = new File(databasePath);
    try {
      this.databaseReader = new DatabaseReader.Builder(databaseFile).withCache(new CHMCache(cacheSize)).build();
    } catch (InvalidDatabaseException e) {
      throw new IllegalArgumentException("The database provided is invalid or corrupted.", e);
    } catch (IOException e) {
      throw new IllegalArgumentException("The database provided was not found in the path", e);
    }

    this.database = Databases.fromDatabaseType(databaseReader.getMetadata().getDatabaseType());
    this.desiredFields = createDesiredFields(fields, !ecsCompatibility.equals("disabled"));
  }

  public static boolean isDatabaseValid(String databasePath) {
    final File database = new File(databasePath);
    try (DatabaseReader ignore = new DatabaseReader.Builder(database).build()) {
      return true;
    } catch (InvalidDatabaseException e) {
      logger.debug("The database provided is invalid or corrupted");
    } catch (IOException e) {
      logger.debug("The database provided was not found in the path");
    }
    return false;
  }

  private Set<Fields> createDesiredFields(List<String> fields, final boolean ecsCompatibilityEnabled) {
    if (fields != null && !fields.isEmpty()) {
      return fields.stream()
              .map(Fields::parseField)
              .collect(Collectors.toCollection(() -> EnumSet.noneOf(Fields.class)));
    }

    if (database == Databases.CITY) {
      return createCityDefaultFields(ecsCompatibilityEnabled);
    }

    return database.getDefaultFields();
  }

  private Set<Fields> createCityDefaultFields(boolean ecsCompatibilityEnabled) {
    // When ECS is disabled, change the default region code field from REGION_ISO_CODE to
    // REGION_CODE (BC)
    if (!ecsCompatibilityEnabled) {
      final EnumSet<Fields> ecsDisabledFields = EnumSet.copyOf(database.getDefaultFields());
      ecsDisabledFields.remove(Fields.REGION_ISO_CODE);
      ecsDisabledFields.add(Fields.REGION_CODE);
      return ecsDisabledFields;
    }

    return database.getDefaultFields();
  }

  public boolean handleEvent(RubyEvent rubyEvent) {
    final Event event = rubyEvent.getEvent();
    Object input = event.getField(sourceField);
    if (input == null) {
      return false;
    }
    String ip;

    if (input instanceof List) {
      ip = (String) ((List) input).get(0);

    } else if (input instanceof String) {
      ip = (String) input;
    } else {
      throw new IllegalArgumentException("Expected input field value to be String or List type");
    }

    if (ip.trim().isEmpty()){
      return false;
    }

    Map<Fields, Object> geoData = new HashMap<>();

    try {
      final InetAddress ipAddress = InetAddress.getByName(ip);
      switch (database) {
        case CITY:
          geoData = retrieveCityGeoData(ipAddress);
          break;
        case COUNTRY:
          geoData = retrieveCountryGeoData(ipAddress);
          break;
        case ASN:
          geoData = retrieveAsnGeoData(ipAddress);
          break;
        case ISP:
          geoData = retrieveIspGeoData(ipAddress);
          break;
        case DOMAIN:
          geoData = retrieveDomainGeoData(ipAddress);
          break;
        case ENTERPRISE:
          geoData = retrieveEnterpriseGeoData(ipAddress);
          break;
        case ANONYMOUS_IP:
          geoData = retrieveAnonymousIpGeoData(ipAddress);
          break;
        default:
          throw new IllegalStateException("Unsupported database type " + databaseReader.getMetadata().getDatabaseType() + "");
      }
    } catch (UnknownHostException e) {
      logger.debug("IP Field contained invalid IP address or hostname. exception={}, field={}, event={}", e, sourceField, event);
    } catch (AddressNotFoundException e) {
      logger.debug("IP not found! exception={}, field={}, event={}", e, sourceField, event);
    } catch (GeoIp2Exception | IOException e) {
      logger.debug("GeoIP2 Exception. exception={}, field={}, event={}", e, sourceField, event);
    }

    return applyGeoData(geoData, event);
  }

  private boolean applyGeoData(Map<Fields, Object> geoData, Event event) {
    if (geoData == null) {
      return false;
    }
    // only do event.set(@target) if the lookup result is not null
    if (event.getField(targetField) == null) {
      event.setField(targetField, Collections.emptyMap());
    }
    // don't do anything more if the lookup result is empty
    if (geoData.isEmpty()) {
      return false;
    }

    String targetFieldReference = "[" + this.targetField + "]";
    for (Map.Entry<Fields, Object> it: geoData.entrySet()) {
      final Fields field = it.getKey();
      final String subFieldReference = this.fieldReferenceExtractor.apply(field);

      if (subFieldReference.equals("[]")) {
        continue; // skip the incompatible ECS field
      }

      event.setField(targetFieldReference + subFieldReference, it.getValue());
    }
    return true;
  }

  private Map<Fields,Object> retrieveCityGeoData(InetAddress ipAddress) throws GeoIp2Exception, IOException {
    CityResponse response = databaseReader.city(ipAddress);
    Country country = response.getCountry();
    City city = response.getCity();
    Location location = response.getLocation();
    Continent continent = response.getContinent();
    Postal postal = response.getPostal();
    Subdivision subdivision = response.getMostSpecificSubdivision();
    Map<Fields, Object> geoData = new EnumMap<>(Fields.class);

    // if location is empty, there is no point populating geo data
    // and most likely all other fields are empty as well
    if (location.getLatitude() == null && location.getLongitude() == null) {
      return geoData;
    }

    for (Fields desiredField : this.desiredFields) {
      switch (desiredField) {
        case CITY_NAME:
          String cityName = city.getName();
          if (cityName != null) {
            geoData.put(Fields.CITY_NAME, cityName);
          }
          break;
        case CONTINENT_CODE:
          String continentCode = continent.getCode();
          if (continentCode != null) {
            geoData.put(Fields.CONTINENT_CODE, continentCode);
          }
          break;
        case CONTINENT_NAME:
          String continentName = continent.getName();
          if (continentName != null) {
            geoData.put(Fields.CONTINENT_NAME, continentName);
          }
          break;
        case COUNTRY_NAME:
          String countryName = country.getName();
          if (countryName != null) {
            geoData.put(Fields.COUNTRY_NAME, countryName);
          }
          break;
        case COUNTRY_CODE2:
          String countryCode2 = country.getIsoCode();
          if (countryCode2 != null) {
            geoData.put(Fields.COUNTRY_CODE2, countryCode2);
          }
          break;
        case COUNTRY_CODE3:
          String countryCode3 = country.getIsoCode();
          if (countryCode3 != null) {
            geoData.put(Fields.COUNTRY_CODE3, countryCode3);
          }
          break;
        case IP:
          geoData.put(Fields.IP, ipAddress.getHostAddress());
          break;
        case POSTAL_CODE:
          String postalCode = postal.getCode();
          if (postalCode != null) {
            geoData.put(Fields.POSTAL_CODE, postalCode);
          }
          break;
        case DMA_CODE:
          Integer dmaCode = location.getMetroCode();
          if (dmaCode != null) {
            geoData.put(Fields.DMA_CODE, dmaCode);
          }
          break;
        case REGION_NAME:
          String subdivisionName = subdivision.getName();
          if (subdivisionName != null) {
            geoData.put(Fields.REGION_NAME, subdivisionName);
          }
          break;
        case REGION_CODE:
          String subdivisionCode = subdivision.getIsoCode();
          if (subdivisionCode != null) {
            geoData.put(Fields.REGION_CODE, subdivisionCode);
          }
          break;
        case REGION_ISO_CODE:
          parseRegionIsoCodeField(country, subdivision)
                  .ifPresent(data -> geoData.put(Fields.REGION_ISO_CODE, data));
          break;
        case TIMEZONE:
          String locationTimeZone = location.getTimeZone();
          if (locationTimeZone != null) {
            geoData.put(Fields.TIMEZONE, locationTimeZone);
          }
          break;
        case LOCATION:
          parseLocationField(location)
                  .ifPresent(data -> geoData.put(Fields.LOCATION, data));
          break;
        case LATITUDE:
          Double lat = location.getLatitude();
          if (lat != null) {
            geoData.put(Fields.LATITUDE, lat);
          }
          break;
        case LONGITUDE:
          Double lon = location.getLongitude();
          if (lon != null) {
            geoData.put(Fields.LONGITUDE, lon);
          }
          break;
      }
    }

    return geoData;
  }

  private Map<Fields,Object> retrieveCountryGeoData(InetAddress ipAddress) throws GeoIp2Exception, IOException {
    CountryResponse response = databaseReader.country(ipAddress);
    Country country = response.getCountry();
    Continent continent = response.getContinent();
    Map<Fields, Object> geoData = new EnumMap<>(Fields.class);

    for (Fields desiredField : this.desiredFields) {
      switch (desiredField) {
        case IP:
          geoData.put(Fields.IP, ipAddress.getHostAddress());
          break;
        case COUNTRY_CODE2:
          String countryCode2 = country.getIsoCode();
          if (countryCode2 != null) {
            geoData.put(Fields.COUNTRY_CODE2, countryCode2);
          }
          break;
        case COUNTRY_NAME:
          String countryName = country.getName();
          if (countryName != null) {
            geoData.put(Fields.COUNTRY_NAME, countryName);
          }
          break;
        case CONTINENT_NAME:
          String continentName = continent.getName();
          if (continentName != null) {
            geoData.put(Fields.CONTINENT_NAME, continentName);
          }
          break;
      }
    }

    return geoData;
  }

  private Map<Fields, Object> retrieveIspGeoData(InetAddress ipAddress) throws GeoIp2Exception, IOException {
    IspResponse response = databaseReader.isp(ipAddress);

    Map<Fields, Object> geoData = new EnumMap<>(Fields.class);
    for (Fields desiredField : this.desiredFields) {
      switch (desiredField) {
        case IP:
          geoData.put(Fields.IP, ipAddress.getHostAddress());
          break;
        case AUTONOMOUS_SYSTEM_NUMBER:
          Long asn = response.getAutonomousSystemNumber();
          if (asn != null) {
            geoData.put(desiredField, asn);
          }
          break;
        case AUTONOMOUS_SYSTEM_ORGANIZATION:
          String aso = response.getAutonomousSystemOrganization();
          if (aso != null) {
            geoData.put(desiredField, aso);
          }
          break;
        case ISP:
          String isp = response.getIsp();
          if (isp != null) {
            geoData.put(Fields.ISP, isp);
          }
          break;
        case ORGANIZATION:
          String org = response.getOrganization();
          if (org != null) {
            geoData.put(Fields.ORGANIZATION, org);
          }
          break;
      }
    }

    return geoData;
  }

  private Map<Fields, Object> retrieveAsnGeoData(InetAddress ipAddress) throws GeoIp2Exception, IOException {
    AsnResponse response = databaseReader.asn(ipAddress);
    Network network = response.getNetwork();

    Map<Fields, Object> geoData = new EnumMap<>(Fields.class);
    for (Fields desiredField : this.desiredFields) {
      switch (desiredField) {
        case IP:
          geoData.put(Fields.IP, ipAddress.getHostAddress());
          break;
        case AUTONOMOUS_SYSTEM_NUMBER:
          Long asn = response.getAutonomousSystemNumber();
          if (asn != null) {
            geoData.put(Fields.AUTONOMOUS_SYSTEM_NUMBER, asn);
          }
          break;
        case AUTONOMOUS_SYSTEM_ORGANIZATION:
          String aso = response.getAutonomousSystemOrganization();
          if (aso != null) {
            geoData.put(Fields.AUTONOMOUS_SYSTEM_ORGANIZATION, aso);
          }
          break;
        case NETWORK:
          if (network != null) {
            geoData.put(Fields.NETWORK, network.toString());
          }
          break;
      }
    }

    return geoData;
  }

  private Map<Fields, Object> retrieveDomainGeoData(InetAddress ipAddress) throws GeoIp2Exception, IOException {
    DomainResponse response = databaseReader.domain(ipAddress);
    Map<Fields, Object> geoData = new EnumMap<>(Fields.class);
    for (Fields desiredField : this.desiredFields) {
      switch (desiredField) {
        case DOMAIN:
          String domain = response.getDomain();
          geoData.put(Fields.DOMAIN, domain);
          break;
      }
    }

    return geoData;
  }

  private Map<Fields, Object> retrieveEnterpriseGeoData(InetAddress ipAddress) throws GeoIp2Exception, IOException {
    EnterpriseResponse response = databaseReader.enterprise(ipAddress);

    Map<Fields, Object> geoData = new EnumMap<>(Fields.class);
    Country country = response.getCountry();
    City city = response.getCity();
    Location location = response.getLocation();
    Continent continent = response.getContinent();
    Subdivision subdivision = response.getMostSpecificSubdivision();

    Long asn = response.getTraits().getAutonomousSystemNumber();
    String organizationName = response.getTraits().getAutonomousSystemOrganization();
    Network network = response.getTraits().getNetwork();

    boolean isHostingProvider = response.getTraits().isHostingProvider();
    boolean isTorExitNode = response.getTraits().isTorExitNode();
    boolean isAnonymousVpn = response.getTraits().isAnonymousVpn();
    boolean isAnonymous = response.getTraits().isAnonymous();
    boolean isPublicProxy = response.getTraits().isPublicProxy();
    boolean isResidentialProxy = response.getTraits().isResidentialProxy();

    for (Fields desiredField : this.desiredFields) {
      switch (desiredField) {
        case IP:
          geoData.put(Fields.IP, ipAddress.getHostAddress());
          break;
        case COUNTRY_CODE2:
          String countryIsoCode = country.getIsoCode();
          if (countryIsoCode != null) {
            geoData.put(desiredField, countryIsoCode);
          }
          break;
        case COUNTRY_NAME:
          String countryName = country.getName();
          if (countryName != null) {
            geoData.put(desiredField, countryName);
          }
          break;
        case CONTINENT_NAME:
          String continentName = continent.getName();
          if (continentName != null) {
            geoData.put(desiredField, continentName);
          }
          break;
        case REGION_ISO_CODE:
          parseRegionIsoCodeField(country, subdivision)
                  .ifPresent(data -> geoData.put(desiredField, data));
          break;
        case REGION_NAME:
          String subdivisionName = subdivision.getName();
          if (subdivisionName != null) {
            geoData.put(desiredField, subdivisionName);
          }
          break;
        case CITY_NAME:
          String cityName = city.getName();
          if (cityName != null) {
            geoData.put(desiredField, cityName);
          }
          break;
        case TIMEZONE:
          String locationTimeZone = location.getTimeZone();
          if (locationTimeZone != null) {
            geoData.put(desiredField, locationTimeZone);
          }
          break;
        case LOCATION:
          parseLocationField(location)
                  .ifPresent(data -> geoData.put(desiredField, data));
          break;
        case AUTONOMOUS_SYSTEM_NUMBER:
          if (asn != null) {
            geoData.put(desiredField, asn);
          }
          break;
        case AUTONOMOUS_SYSTEM_ORGANIZATION:
          if (organizationName != null) {
            geoData.put(desiredField, organizationName);
          }
          break;
        case NETWORK:
          if (network != null) {
            geoData.put(desiredField, network.toString());
          }
          break;
        case HOSTING_PROVIDER:
          geoData.put(desiredField, isHostingProvider);
          break;
        case TOR_EXIT_NODE:
          geoData.put(desiredField, isTorExitNode);
          break;
        case ANONYMOUS_VPN:
          geoData.put(desiredField, isAnonymousVpn);
          break;
        case ANONYMOUS:
          geoData.put(desiredField, isAnonymous);
          break;
        case PUBLIC_PROXY:
          geoData.put(desiredField, isPublicProxy);
          break;
        case RESIDENTIAL_PROXY:
          geoData.put(desiredField, isResidentialProxy);
          break;
      }
    }
    return geoData;
  }

  private Map<Fields, Object> retrieveAnonymousIpGeoData(final InetAddress ipAddress) throws GeoIp2Exception, IOException {
    AnonymousIpResponse response = databaseReader.anonymousIp(ipAddress);

    Map<Fields, Object> geoData = new EnumMap<>(Fields.class);
    boolean isHostingProvider = response.isHostingProvider();
    boolean isTorExitNode = response.isTorExitNode();
    boolean isAnonymousVpn = response.isAnonymousVpn();
    boolean isAnonymous = response.isAnonymous();
    boolean isPublicProxy = response.isPublicProxy();
    boolean isResidentialProxy = response.isResidentialProxy();

    for (Fields desiredField : this.desiredFields) {
      switch (desiredField) {
        case IP:
          geoData.put(desiredField, ipAddress.getHostAddress());
          break;
        case HOSTING_PROVIDER:
          geoData.put(desiredField, isHostingProvider);
          break;
        case TOR_EXIT_NODE:
          geoData.put(desiredField, isTorExitNode);
          break;
        case ANONYMOUS_VPN:
          geoData.put(desiredField, isAnonymousVpn);
          break;
        case ANONYMOUS:
          geoData.put(desiredField, isAnonymous);
          break;
        case PUBLIC_PROXY:
          geoData.put(desiredField, isPublicProxy);
          break;
        case RESIDENTIAL_PROXY:
          geoData.put(desiredField, isResidentialProxy);
          break;
      }
    }
    return geoData;
  }

  private Optional<Map<String, Object>> parseLocationField(Location location) {
    Double latitude = location.getLatitude();
    Double longitude = location.getLongitude();
    if (latitude != null && longitude != null) {
      Map<String, Object> locationObject = new HashMap<>();
      locationObject.put("lat", latitude);
      locationObject.put("lon", longitude);
      return Optional.of(locationObject);
    }

    return Optional.empty();
  }

  private Optional<String> parseRegionIsoCodeField(final Country country, final Subdivision subdivision) {
    String countryCodeForRegion = country.getIsoCode();
    String regionCode2 = subdivision.getIsoCode();
    if (countryCodeForRegion != null && regionCode2 != null) {
      return Optional.of(String.format("%s-%s", countryCodeForRegion, regionCode2));
    }

    return Optional.empty();
  }

  @Override
  public void close() {
    if (databaseReader != null) {
      try {
        databaseReader.close();
      } catch (IOException e) {
        // Ignore
      }
    }
  }
}
