def get_file_path(filename)
  ::File.join(::File.expand_path("../../vendor/", ::File.dirname(__FILE__)), filename)
end

DEFAULT_CITY_DB_PATH = get_file_path("GeoLite2-City.mmdb")
DEFAULT_ASN_DB_PATH = get_file_path("GeoLite2-ASN.mmdb")
METADATA_PATH = get_file_path("metadata.csv")
DEFAULT_CITY_DB_NAME = "GeoLite2-City.mmdb"
DEFAULT_ASN_DB_NAME = "GeoLite2-ASN.mmdb"
SECOND_CITY_DB_NAME = "GeoLite2-City_20200220.mmdb"
GEOIP_STAGING_HOST = "https://paisano-staging.elastic.dev"
GEOIP_STAGING_ENDPOINT = "#{GEOIP_STAGING_HOST}/v1/geoip/database/"

def write_temp_metadata(temp_file_path, row = nil)
  now = Time.now.to_i
  city = md5(DEFAULT_CITY_DB_PATH)
  asn = md5(DEFAULT_ASN_DB_PATH)

  metadata = []
  metadata << ["ASN",now,"",asn,DEFAULT_ASN_DB_NAME]
  metadata << ["City",now,"",city,DEFAULT_CITY_DB_NAME]
  metadata << row if row
  CSV.open temp_file_path, 'w' do |csv|
    metadata.each { |row| csv << row }
  end
end

def city2_metadata
  ["City",Time.now.to_i,"",md5(DEFAULT_CITY_DB_PATH),SECOND_CITY_DB_NAME]
end

def copy_city_database(filename)
  new_path = DEFAULT_CITY_DB_PATH.gsub(DEFAULT_CITY_DB_NAME, filename)
  FileUtils.cp(DEFAULT_CITY_DB_PATH, new_path)
end

def md5(file_path)
  Digest::MD5.hexdigest(::File.read(file_path))
end