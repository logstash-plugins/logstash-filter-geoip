# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "tempfile"

# The GeoIP filter adds information about the geographical location of IP addresses,

# java jar files reside in ../../geoip2-*/lib/
require "java"

require_relative "../../geoip2-2.2.0/lib/geoip2-2.2.0.jar"
require_relative "../../geoip2-2.2.0/lib/jackson-databind-2.5.3.jar"
require_relative "../../geoip2-2.2.0/lib/jackson-core-2.5.3.jar"
require_relative "../../geoip2-2.2.0/lib/maxmind-db-1.0.0.jar"
require_relative "../../geoip2-2.2.0/lib/jackson-annotations-2.5.0.jar"


java_import "java.net.InetAddress"
java_import "com.maxmind.geoip2.DatabaseReader"
java_import "com.maxmind.geoip2.model.CityResponse"
java_import "com.maxmind.geoip2.record.Country"
java_import "com.maxmind.geoip2.record.Subdivision"
java_import "com.maxmind.geoip2.record.City"
java_import "com.maxmind.geoip2.record.Postal"
java_import "com.maxmind.geoip2.record.Location"

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
# Logstash releases ship with the GeoLiteCity database made available from
# Maxmind with a CCA-ShareAlike 3.0 license. For more details on GeoLite, see
# <http://www.maxmind.com/en/geolite>.
class LogStash::Filters::GeoIP2 < LogStash::Filters::Base
  config_name "geoip2"

  # The path to the GeoIP database file which Logstash should use. Country, City, ASN, ISP
  # and organization databases are supported.
  #
  # If not specified, this will default to the GeoLiteCity database that ships
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
  # `city_name`, `continent_code`, `country_code2`, `country_code3`, `country_name`,
  # `dma_code`, `ip`, `latitude`, `longitude`, `postal_code`, `region_name` and `timezone`.
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

      if !File.exists?(@database)
        raise "You must specify 'database => ...' in your geoip filter (I looked for '#{@database}'"
      end
    end
    @logger.info("Using geoip database", :path => @database)

    db_file = JavaIO::File.new(@database)
    geoip2_initialize = DatabaseReader::Builder.new(db_file).build();

    @threadkey = "geoip2-#{self.object_id}"
  end # def register

  public
  def filter(event)
    return unless filter?(event)

    if !Thread.current.key?(@threadkey)
      db_file = JavaIO::File.new(@database)
      Thread.current[@threadkey] = DatabaseReader::Builder.new(db_file).build();
    end

    begin
      ip = event[@source]
      ip = ip.first if ip.is_a? Array
      ipAddress = InetAddress.getByName(ip)
      response = Thread.current[@threadkey].city(ipAddress)
      country = response.getCountry()
      subdivision = response.getMostSpecificSubdivision()
      city = response.getCity()
      postal = response.getPostal()
      location = response.getLocation()

      geo_data_hash = Hash.new()
      geo_data_hash = { "country" => country.getName(), "region" => subdivision.getName(), "city" => city.getName(), "postal" => postal.getCode(), "latitude" => location.getLatitude(), "longitude" => location.getLongitude()}

    rescue com.maxmind.geoip2.exception.AddressNotFoundException => e
      # Address Not Found
      return
    rescue java.net.UnknownHostException => e
      @logger.error("IP Field contained invalid IP address or hostname", :field => @field, :event => event)
      return
    rescue Exception => e
      @logger.error("Unknown error while looking up GeoIP data", :exception => e, :field => @field, :event => event)
      return
    end

    event[@target] = {} if event[@target].nil?
    geo_data_hash.each do |key, value|
      next if value.nil? || (value.is_a?(String) && value.empty?)
      if @fields.nil? || @fields.empty? || @fields.include?(key.to_s)
        # convert key to string (normally a Symbol)
        if value.is_a?(String)
          # Some strings from GeoIP don't have the correct encoding...
          value = case value.encoding
            # I have found strings coming from GeoIP that are ASCII-8BIT are actually
            # ISO-8859-1...
            when Encoding::ASCII_8BIT; value.force_encoding(Encoding::ISO_8859_1).encode(Encoding::UTF_8)
            when Encoding::ISO_8859_1, Encoding::US_ASCII;  value.encode(Encoding::UTF_8)
            else; value
          end
        end
        event[@target][key.to_s] = value
      end
    end # geo_data_hash.each
    if event[@target].key?('latitude') && event[@target].key?('longitude')
      # If we have latitude and longitude values, add the location field as GeoJSON array
      event[@target]['location'] = [ event[@target]["longitude"].to_f, event[@target]["latitude"].to_f ]
    end
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::GeoIP
