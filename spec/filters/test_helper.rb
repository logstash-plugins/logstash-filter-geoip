require "logstash-core/logstash-core"
require "digest"
require "csv"

# Since we use Logstash's x-pack WITHOUT the LogStash::Runner,
# we must find it relative to logstash-core and add it to the load path.
require 'pathname'
logstash_core_path = Gem.loaded_specs['logstash-core']&.full_gem_path or fail("logstash-core lib not found")
logstash_xpack_load_path = Pathname.new(logstash_core_path).join("../x-pack/lib").cleanpath.to_s
if ENV['OSS'] == "true" || !File.exists?(logstash_xpack_load_path)
  $stderr.puts("X-PACK is not available")
  LogStash::OSS = true
else
  if !$LOAD_PATH.include?(logstash_xpack_load_path)
    $stderr.puts("ADDING LOGSTASH X-PACK to load path: #{logstash_xpack_load_path}")
    $LOAD_PATH.unshift(logstash_xpack_load_path)
  end
  LogStash::OSS = false

  # when running in a Logstash process that has a geoip extension available, it will
  # be loaded before this plugin is instantiated. In tests, we need to find and load the
  # appropriate extension ourselves.
  extension = nil
  extension ||= begin; require 'geoip_database_management/extension'; LogStash::const_get("GeoipDatabaseManagement::Extension"); rescue Exception; nil; end
  extension ||= begin; require 'filters/geoip/extension'; LogStash::const_get("Filters::Geoip::Extension"); rescue Exception; nil; end
  if extension
    $stderr.puts("loading logstash extension for geoip: #{extension}")
    extension.new.tap do |instance|
      # the extensions require logstash/runner even though they don't need to,
      # resulting in _all_ extensions being loaded into the registry, including
      # those whose dependencies are not met by this plugin's dependency graph.
      def instance.require(path)
        super unless path == "logstash/runner"
      end
    end.additionals_settings(LogStash::SETTINGS)
  else
    $stderr.puts("no logstash extension for geoip is available")
  end
end

def get_vendor_path(filename)
  ::File.join(::File.expand_path("../../vendor/", ::File.dirname(__FILE__)), filename)
end

DEFAULT_CITY_DB_PATH = get_vendor_path("GeoLite2-City.mmdb")
DEFAULT_ASN_DB_PATH = get_vendor_path("GeoLite2-ASN.mmdb")

major, minor = LOGSTASH_VERSION.split(".")
MAJOR = major.to_i
MINOR = minor.to_i
