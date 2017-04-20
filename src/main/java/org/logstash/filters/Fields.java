package org.logstash.filters;

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

import java.util.Arrays;
import java.util.EnumSet;
import java.util.Locale;

enum Fields {
  AUTONOMOUS_SYSTEM_NUMBER("asn"),
  AUTONOMOUS_SYSTEM_ORGANIZATION("as_org"),
  CITY_NAME("city_name"),
  COUNTRY_NAME("country_name"),
  CONTINENT_CODE("continent_code"),
  CONTINENT_NAME("continent_name"),
  COUNTRY_CODE2("country_code2"),
  COUNTRY_CODE3("country_code3"),
  IP("ip"),
  ISP("isp"),
  POSTAL_CODE("postal_code"),
  DMA_CODE("dma_code"),
  REGION_NAME("region_name"),
  REGION_CODE("region_code"),
  TIMEZONE("timezone"),
  LOCATION("location"),
  LATITUDE("latitude"),
  LONGITUDE("longitude"),
  ORGANIZATION("organization");

  private String fieldName;

  Fields(String fieldName) {
    this.fieldName = fieldName;
  }

  public String fieldName() {
    return fieldName;
  }

  static final EnumSet<Fields> ALL_FIELDS = EnumSet.allOf(Fields.class);

  static final EnumSet<Fields> DEFAULT_CITY_FIELDS = EnumSet.of(Fields.IP, Fields.CITY_NAME,
      Fields.CONTINENT_CODE, Fields.COUNTRY_NAME, Fields.COUNTRY_CODE2,
      Fields.COUNTRY_CODE3, Fields.IP, Fields.POSTAL_CODE, Fields.DMA_CODE, Fields.REGION_NAME,
      Fields.REGION_CODE, Fields.TIMEZONE, Fields.LOCATION, Fields.LATITUDE, Fields.LONGITUDE);

  static final EnumSet<Fields> DEFAULT_COUNTRY_FIELDS = EnumSet.of(Fields.IP, Fields.COUNTRY_CODE2,
      Fields.IP, Fields.COUNTRY_NAME, Fields.CONTINENT_NAME);

  static final EnumSet<Fields> DEFAULT_ISP_FIELDS = EnumSet.of(Fields.IP, Fields.AUTONOMOUS_SYSTEM_NUMBER,
      Fields.AUTONOMOUS_SYSTEM_ORGANIZATION, Fields.ISP, Fields.ORGANIZATION);

  public static Fields parseField(String value) {
    try {
      return valueOf(value.toUpperCase(Locale.ROOT));
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("illegal field value " + value + ". valid values are " +
          Arrays.toString(ALL_FIELDS.toArray()));
    }
  }
}
