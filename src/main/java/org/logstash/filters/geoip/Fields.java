package org.logstash.filters.geoip;

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

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

enum Fields {

  AUTONOMOUS_SYSTEM_NUMBER("as.number", "asn"),
  AUTONOMOUS_SYSTEM_ORGANIZATION("as.organization.name", "as_org"),
  CITY_NAME("geo.city_name", "city_name"),
  COUNTRY_NAME("geo.country_name", "country_name"),
  CONTINENT_CODE("geo.continent_code", "continent_code"),
  CONTINENT_NAME("geo.continent_name", "continent_name"),
  COUNTRY_CODE2("geo.country_iso_code", "country_code2"),
  COUNTRY_CODE3("", "country_code3"), // `country_code3` is not ECS compatible and will be skipped in ECS mode
  DOMAIN("domain"),
  IP("ip"),
  ISP("mmdb.isp", "isp"),
  POSTAL_CODE("geo.postal_code", "postal_code"),
  DMA_CODE("mmdb.dma_code", "dma_code"),
  REGION_NAME("geo.region_name", "region_name"),
  REGION_CODE("geo.region_code", "region_code"),
  REGION_ISO_CODE("geo.region_iso_code", "region_iso_code"),
  TIMEZONE("geo.timezone", "timezone"),
  LOCATION("geo.location", "location"),
  LATITUDE("geo.location.lat", "latitude"),
  LONGITUDE("geo.location.lon", "longitude"),
  ORGANIZATION("mmdb.organization", "organization"),
  NETWORK("traits.network", "network"),
  HOSTING_PROVIDER("traits.hosting_provider", "hosting_provider"),
  TOR_EXIT_NODE("traits.tor_exit_node", "tor_exit_node"),
  ANONYMOUS_VPN("traits.anonymous_vpn", "anonymous_vpn"),
  ANONYMOUS("traits.anonymous", "anonymous"),
  PUBLIC_PROXY("traits.public_proxy", "public_proxy"),
  RESIDENTIAL_PROXY("traits.residential_proxy", "residential_proxy");

  private final String fieldName;
  private final String ecsFieldName;

  private final String fieldReferenceLegacy;
  private final String fieldReferenceECSv1;

  @Deprecated
  Fields(String fieldName) {
    this(fieldName, fieldName);
  }

  Fields(final String ecsFieldName, final String legacyFieldName) {
    this.ecsFieldName = ecsFieldName;
    this.fieldName = legacyFieldName;

    this.fieldReferenceLegacy = normalizeFieldReferenceFragment(fieldName);
    this.fieldReferenceECSv1 = normalizeFieldReferenceFragment(ecsFieldName);
  }

  public String fieldName() {
    return fieldName;
  }

  public String getEcsFieldName() {
    return this.ecsFieldName;
  }

  public String getFieldReferenceLegacy() {
    return this.fieldReferenceLegacy;
  }

  public String getFieldReferenceECSv1() {
    return this.fieldReferenceECSv1;
  }

  public static Fields parseField(String value) {
    final String candidate = value.toUpperCase(Locale.ROOT);
    try {
      return Fields.valueOf(candidate);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("illegal field value " + value + ". valid values are " +
              Arrays.toString(Fields.values()));
    }
  }

  /**
   * Normalizes a dot-separated field path into a bracket-notation Logstash Field Reference
   * @param fieldName: a dot-separated field path (e.g., `geo.location.lat`)
   * @return a bracket-notation Field Reference (e.g., `[geo][location][lat]`)
   */
  static String normalizeFieldReferenceFragment(final String fieldName) {
    return  Stream.of(fieldName.split("\\."))
            .map((f) -> "[" + f + "]")
            .collect(Collectors.joining());
  }
}
