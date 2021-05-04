require "logstash-core/logstash-core"
require "digest"
require "csv"

def get_vendor_path(filename)
  ::File.join(::File.expand_path("../../vendor/", ::File.dirname(__FILE__)), filename)
end

def get_data_dir
  ::File.join(LogStash::SETTINGS.get_value("path.data"), "plugins", "filters", "geoip")
end

def get_file_path(filename)
  ::File.join(get_data_dir, filename)
end

def get_metadata_city_database_name
  if ::File.exist?(METADATA_PATH)
    city = ::CSV.read(METADATA_PATH, headers: false).select { |row| row[0].eql?("City") }.last
    city[4]
  else
    nil
  end
end

METADATA_PATH = get_file_path("metadata.csv")
DEFAULT_CITY_DB_PATH = get_vendor_path("GeoLite2-City.mmdb")
DEFAULT_ASN_DB_PATH = get_vendor_path("GeoLite2-ASN.mmdb")

major, minor = LOGSTASH_VERSION.split(".")
MAJOR = major.to_i
MINOR = minor.to_i
