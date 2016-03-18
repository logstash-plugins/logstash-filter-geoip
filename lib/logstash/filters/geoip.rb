# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

require "java"

require_relative "../../geoip2-2.5.0/lib/geoip2-2.5.0.jar"
require_relative "../../geoip2-2.5.0/lib/jackson-databind-2.6.4.jar"
require_relative "../../geoip2-2.5.0/lib/jackson-core-2.6.4.jar"
require_relative "../../geoip2-2.5.0/lib/maxmind-db-1.1.0.jar"
require_relative "../../geoip2-2.5.0/lib/jackson-annotations-2.6.0.jar"

java_import "java.net.InetAddress"
java_import "com.maxmind.geoip2.DatabaseReader"
java_import "com.maxmind.geoip2.model.CityResponse"
java_import "com.maxmind.geoip2.record.Country"
java_import "com.maxmind.geoip2.record.Subdivision"
java_import "com.maxmind.geoip2.record.City"
java_import "com.maxmind.geoip2.record.Postal"
java_import "com.maxmind.geoip2.record.Location"
java_import "com.maxmind.db.CHMCache"

# create a new instance of the Java class File without shadowing the Ruby version of the File class
module JavaIO
  include_package "java.io"
end

# The GeoIP2 filter adds information about the geographical location of IP addresses,
# based on data from the Maxmind database.
#
# Starting with version 1.3.0 of Logstash, a `[geoip][location]` field is created if
# the GeoIP lookup returns a latitude and longitude. The field is stored in
# http://geojson.org/geojson-spec.html[GeoJSON] format. Additionally,
# the default Elasticsearch template provided with the
# <<plugins-outputs-elasticsearch,`elasticsearch` output>> maps
# the `[geoip][location]` field to an http://www.elasticsearch.org/guide/en/elasticsearch/reference/current/mapping-geo-point-type.html#_mapping_options[Elasticsearch geo_point].
#
# As this field is a `geo_point` _and_ it is still valid GeoJSON, you get
# the awesomeness of Elasticsearch's geospatial query, facet and filter functions
# and the flexibility of having GeoJSON for all other applications (like Kibana's
# map visualization).
#
# This product includes GeoLite2 data created by MaxMind, available from
# <http://dev.maxmind.com/geoip/geoip2/geolite2/>.
class LogStash::Filters::GeoIP < LogStash::Filters::Base
  config_name "geoip"

  # The path to the GeoIP2 database file which Logstash should use. Only City database is supported by now.
  #
  # If not specified, this will default to the world_city_geoip2 database that ships
  # with Logstash.
  config :database, :validate => :path

  # The field containing the IP address or hostname to map via geoip. If
  # this field is an array, only the first value will be used.
  config :source, :validate => :string, :required => true

  # An array of geoip fields to be included in the event.
  #
  # Possible fields depend on the database type. By default, all geoip fields
  # are included in the event.
  #
  # For the built-in GeoLiteCity database, the following are available:
  # `city\_name`, `continent\_code`, `country\_code2`, `country\_code3`, `country\_name`,
  # `dma\_code`, `ip`, `latitude`, `longitude`, `postal\_code`, `region\_name` and `timezone`.
  config :fields, :validate => :array

  # Specify the field into which Logstash should store the geoip data.
  # This can be useful, for example, if you have `src\_ip` and `dst\_ip` fields and
  # would like the GeoIP information of both IPs.
  #
  # If you save the data to a target field other than `geoip` and want to use the
  # `geo\_point` related functions in Elasticsearch, you need to alter the template
  # provided with the Elasticsearch output and configure the output to use the
  # new template.
  #
  # Even if you don't use the `geo\_point` mapping, the `[target][location]` field
  # is still valid GeoJSON.
  config :target, :validate => :string, :default => 'geoip'

  public
  def register
    if @database.nil?
      @database = ::Dir.glob(::File.join(::File.expand_path("../../../vendor/", ::File.dirname(__FILE__)),"GeoLite2-City.mmdb")).first

      if @database.nil? || !File.exists?(@database)
        raise "You must specify 'database => ...' in your geoip filter (I looked for '#{@database}')"
      end
    end

    @logger.info("Using geoip database", :path => @database)

    db_file = JavaIO::File.new(@database)
    @parser = DatabaseReader::Builder.new(db_file).withCache(CHMCache.new()).build();
  end # def register

  public
  def filter(event)
    return unless filter?(event)

    begin
      ip = event[@source]
      ip = ip.first if ip.is_a? Array
      ip_address = InetAddress.getByName(ip)
      response = @parser.city(ip_address)
      country = response.getCountry()
      subdivision = response.getMostSpecificSubdivision()
      city = response.getCity()
      postal = response.getPostal()
      location = response.getLocation()

      geo_data_hash = Hash.new()

      if @fields.nil? || @fields.empty? || @fields.include?(:city_name)
        geo_data_hash["city_name"] = city.getName()
      end

      if @fields.nil? || @fields.empty? || @fields.include?(:country_name)
        geo_data_hash["country_name"] = country.getName()
      end

      if @fields.nil? || @fields.empty? || @fields.include?(:continent_code)
        geo_data_hash["continent_code"] = response.getContinent().getCode()
      end

      if @fields.nil? || @fields.empty? || @fields.include?(:continent_name)
        geo_data_hash["continent_name"] = response.getContinent().getName()
      end

      if @fields.nil? || @fields.empty? || @fields.include?(:country_code2)
        geo_data_hash["country_code2"] = country.getIsoCode()
      end

      if @fields.nil? || @fields.empty? || @fields.include?(:country_code3)
        geo_data_hash["country_code3"] = country.getIsoCode()
      end

      if @fields.nil? || @fields.empty? || @fields.include?(:ip)
        geo_data_hash["ip"] = ip_address.getHostAddress()
      end

      if @fields.nil? || @fields.empty? || @fields.include?(:postal_code)
        geo_data_hash["postal_code"] = postal.getCode()
      end

      if @fields.nil? || @fields.empty? || @fields.include?(:dma_code)
        geo_data_hash["dma_code"] = location.getMetroCode()
      end

      if @fields.nil? || @fields.empty? || @fields.include?(:region_name)
        geo_data_hash["region_name"] = subdivision.getName()
      end

      if @fields.nil? || @fields.empty? || @fields.include?(:region_code)
        geo_data_hash["region_code"] = subdivision.getIsoCode()
      end

      if @fields.nil? || @fields.empty? || @fields.include?(:timezone)
        geo_data_hash["timezone"] = location.getTimeZone()
      end

      if @fields.nil? || @fields.empty? || @fields.include?(:location)
        geo_data_hash["location"] = [ location.getLongitude(), location.getLatitude() ]
      end

      if @fields.nil? || @fields.empty? || @fields.include?(:latitude)
        geo_data_hash["latitude"] = location.getLatitude()
      end

      if @fields.nil? || @fields.empty? || @fields.include?(:longitude)
        geo_data_hash["longitude"] = location.getLongitude()
      end

    rescue com.maxmind.geoip2.exception.AddressNotFoundException => e
      @logger.debug("IP not found!", :field => @field, :event => event)
      return
    rescue java.net.UnknownHostException => e
      @logger.error("IP Field contained invalid IP address or hostname", :field => @field, :event => event)
      return
    rescue Exception => e
      @logger.error("Unknown error while looking up GeoIP data", :exception => e, :field => @field, :event => event)
      return
    end

    event[@target] = geo_data_hash

    filter_matched(event)
  end # def filter
end # class LogStash::Filters::GeoIP
