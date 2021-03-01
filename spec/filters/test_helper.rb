require "logstash-core/logstash-core"
require "digest"

def get_vendor_path
  ::File.expand_path("../../vendor/", ::File.dirname(__FILE__))
end

def get_file_path(filename)
  ::File.join(get_vendor_path, filename)
end

def get_metadata_database_name
  ::File.exist?(METADATA_PATH) ? ::File.read(METADATA_PATH).split(",").last[0..-2] : nil
end

METADATA_PATH = get_file_path("metadata.csv")
DEFAULT_CITY_DB_PATH = get_file_path("GeoLite2-City.mmdb")
DEFAULT_ASN_DB_PATH = get_file_path("GeoLite2-ASN.mmdb")

major, minor = LOGSTASH_VERSION.split(".")
MAJOR = major.to_i
MINOR = minor.to_i
