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
import com.maxmind.geoip2.exception.AddressNotFoundException;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.AsnResponse;
import com.maxmind.geoip2.model.CityResponse;
import com.maxmind.geoip2.model.CountryResponse;
import com.maxmind.geoip2.model.DomainResponse;
import com.maxmind.geoip2.model.IspResponse;
import com.maxmind.geoip2.record.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.logstash.Event;

import com.maxmind.geoip2.DatabaseReader;
import org.logstash.ext.JrubyEventExtLibrary.RubyEvent;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;
import java.util.function.Function;

public class GeoIPFilter {
  private static Logger logger = LogManager.getLogger();
  // The free GeoIP2 databases
  private static final String CITY_LITE_DB_TYPE = "GeoLite2-City";
  private static final String COUNTRY_LITE_DB_TYPE = "GeoLite2-Country";
  private static final String ASN_LITE_DB_TYPE = "GeoLite2-ASN";

  // The paid GeoIP2 databases
  private static final String CITY_DB_TYPE = "GeoIP2-City";
  private static final String CITY_AFRICA_DB_TYPE = "GeoIP2-City-Africa";
  private static final String CITY_ASIA_PACIFIC_DB_TYPE = "GeoIP2-City-Asia-Pacific";
  private static final String CITY_EUROPE_DB_TYPE = "GeoIP2-City-Europe";
  private static final String CITY_NORTH_AMERICA_DB_TYPE = "GeoIP2-City-North-America";
  private static final String CITY_SOUTH_AMERICA_DB_TYPE = "GeoIP2-City-South-America";
  private static final String COUNTRY_DB_TYPE = "GeoIP2-Country";
  private static final String ISP_DB_TYPE = "GeoIP2-ISP";
  private static final String DOMAIN_DB_TYPE = "GeoIP2-Domain";

  private final String sourceField;
  private final String targetField;
  private final Set<Fields> desiredFields;
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

    final File database = new File(databasePath);
    try {
      this.databaseReader = new DatabaseReader.Builder(database).withCache(new CHMCache(cacheSize)).build();
    } catch (InvalidDatabaseException e) {
      throw new IllegalArgumentException("The database provided is invalid or corrupted.", e);
    } catch (IOException e) {
      throw new IllegalArgumentException("The database provided was not found in the path", e);
    }
    this.desiredFields = createDesiredFields(fields, !ecsCompatibility.equals("disabled"));
  }

  public static boolean isDatabaseValid(String databasePath) {
    final File database = new File(databasePath);
    try {
      new DatabaseReader.Builder(database).build();
      return true;
    } catch (InvalidDatabaseException e) {
      logger.debug("The database provided is invalid or corrupted");
    } catch (IOException e) {
      logger.debug("The database provided was not found in the path");
    }
    return false;
  }

  private Set<Fields> createDesiredFields(List<String> fields, final boolean ecsCompatibilityEnabled) {
    Set<Fields> desiredFields = EnumSet.noneOf(Fields.class);
    if (fields == null || fields.isEmpty()) {
      switch (databaseReader.getMetadata().getDatabaseType()) {
        case CITY_LITE_DB_TYPE:
        case CITY_DB_TYPE:
        case CITY_AFRICA_DB_TYPE:
        case CITY_ASIA_PACIFIC_DB_TYPE:
        case CITY_EUROPE_DB_TYPE:
        case CITY_NORTH_AMERICA_DB_TYPE:
        case CITY_SOUTH_AMERICA_DB_TYPE:
          desiredFields = ecsCompatibilityEnabled ? Fields.DEFAULT_ECS_CITY_FIELDS : Fields.DEFAULT_CITY_FIELDS;
          break;
        case COUNTRY_LITE_DB_TYPE:
        case COUNTRY_DB_TYPE:
          desiredFields = Fields.DEFAULT_COUNTRY_FIELDS;
          break;
        case ISP_DB_TYPE:
          desiredFields = Fields.DEFAULT_ISP_FIELDS;
          break;
        case ASN_LITE_DB_TYPE:
          desiredFields = Fields.DEFAULT_ASN_LITE_FIELDS;
          break;
        case DOMAIN_DB_TYPE:
          desiredFields = Fields.DEFAULT_DOMAIN_FIELDS;
      }
    } else {
      for (String fieldName : fields) {
        desiredFields.add(Fields.parseField(fieldName));
      }
    }
    return desiredFields;
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
      switch (databaseReader.getMetadata().getDatabaseType()) {
        case CITY_LITE_DB_TYPE:
        case CITY_DB_TYPE:
        case CITY_AFRICA_DB_TYPE:
        case CITY_ASIA_PACIFIC_DB_TYPE:
        case CITY_EUROPE_DB_TYPE:
        case CITY_NORTH_AMERICA_DB_TYPE:
        case CITY_SOUTH_AMERICA_DB_TYPE:
          geoData = retrieveCityGeoData(ipAddress);
          break;
        case COUNTRY_LITE_DB_TYPE:
        case COUNTRY_DB_TYPE:
          geoData = retrieveCountryGeoData(ipAddress);
          break;
        case ASN_LITE_DB_TYPE:
          geoData = retrieveAsnGeoData(ipAddress);
          break;
        case ISP_DB_TYPE:
          geoData = retrieveIspGeoData(ipAddress);
          break;
        case DOMAIN_DB_TYPE:
          geoData = retrieveDomainGeoData(ipAddress);
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
    Map<Fields, Object> geoData = new HashMap<>();

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
          String countryCodeForRegion = country.getIsoCode();
          String regionCode2 = subdivision.getIsoCode();
          if (countryCodeForRegion != null && regionCode2 != null) {
            geoData.put(Fields.REGION_ISO_CODE, String.format("%s-%s", countryCodeForRegion, regionCode2));
          }
          break;
        case TIMEZONE:
          String locationTimeZone = location.getTimeZone();
          if (locationTimeZone != null) {
            geoData.put(Fields.TIMEZONE, locationTimeZone);
          }
          break;
        case LOCATION:
          Double latitude = location.getLatitude();
          Double longitude = location.getLongitude();
          if (latitude != null && longitude != null) {
            Map<String, Object> locationObject = new HashMap<>();
            locationObject.put("lat", latitude);
            locationObject.put("lon", longitude);
            geoData.put(Fields.LOCATION, locationObject);
          }
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
    Map<Fields, Object> geoData = new HashMap<>();

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

    Map<Fields, Object> geoData = new HashMap<>();
    for (Fields desiredField : this.desiredFields) {
      switch (desiredField) {
        case IP:
          geoData.put(Fields.IP, ipAddress.getHostAddress());
          break;
        case AUTONOMOUS_SYSTEM_NUMBER:
          Integer asn = response.getAutonomousSystemNumber();
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
    Map<Fields, Object> geoData = new HashMap<>();
    for (Fields desiredField : this.desiredFields) {
      switch (desiredField) {
        case IP:
          geoData.put(Fields.IP, ipAddress.getHostAddress());
          break;
        case AUTONOMOUS_SYSTEM_NUMBER:
          Integer asn = response.getAutonomousSystemNumber();
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
      }
    }

    return geoData;
  }

  private Map<Fields, Object> retrieveDomainGeoData(InetAddress ipAddress) throws GeoIp2Exception, IOException {
    DomainResponse response = databaseReader.domain(ipAddress);
    Map<Fields, Object> geoData = new HashMap<>();
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
}
