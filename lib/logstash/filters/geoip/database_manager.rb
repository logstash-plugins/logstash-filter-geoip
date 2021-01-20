require "logstash/util/loggable"
require "logstash/agent"
require "csv"
require "digest"
require "faraday"
require "json"
require "zlib"
require "stud/try"
require "down"
require "rufus/scheduler"

# The mission of DatabaseManager is to ensure the plugin running an up-to-date MaxMind database and thus users are compliant with EULA.
# DM does a daily checking by calling an endpoint to notice a version update.
# It records the update timestamp and md5 of the database in the metadata file to keep track of versions and the number of days disconnects to the endpoint.
# Once a new database version release, DM downloads it, and GeoIP Filter uses it on-the-fly.
# If the last update timestamp is 25 days ago, a warning message shows in the log; if it is 30 days ago, the GeoIP Filter should shutdown in order to be compliant.
# There are online mode and offline mode in DM. `online` is for automatic database update while `offline` is for static database path provided by users or Logstash running in <= 7.11
module LogStash module Filters module Geoip class DatabaseManager
  include LogStash::Util::Loggable

  def initialize(geoip, database_path, database_type)
    @geoip = geoip
    @mode = get_mode(database_path)
    @metadata_path = get_file_path("metadata.csv")
    @database_type = database_type
    @database_path = patch_database_path(database_path)

    if @mode == :online
      raise "logstash-filter-geoip is under elastic Basic License. You are running in open source version, hence the pipeline stops" if LogStash::OSS

      clean_up_database
      setup_metadata
      execute_download_check

      # check database update periodically. trigger `call` method
      @scheduler = Rufus::Scheduler.new({:max_work_threads => 1})
      @scheduler.every('24h', self)
    else
      logger.info("You are running GeoIP plugin in offline mode. Logstash will not check for new database update.")
    end
  end

  GEOIP_HOST = "https://paisano.elastic.dev".freeze
  GEOIP_ENDPOINT = "#{GEOIP_HOST}/v1/geoip/database/".freeze
  DEFAULT_DATABASE_FILENAME = ["GeoLite2-ASN.mmdb", "GeoLite2-City.mmdb"].freeze

  public
  # Check available update and download it. Unzip and validate the file.
  # Update timestamp if calling the server successfully
  # return true for update, false for no update
  def execute_download_check
    begin
      has_update, database_info = check_update

      if has_update
        zip_path = download_database(database_info)
        new_database_path = unzip(zip_path)
        assert_database(new_database_path)
        @database_path = new_database_path
      end

      save_timestamp
      has_update
    rescue => e
      logger.error(e.message, :cause => e.cause, :backtrace => e.backtrace)
      check_age
      false
    end
  end

  # scheduler callback
  def call(job, time)
    logger.info "scheduler database checking"

    begin
      if execute_download_check
        @geoip.setup_filter_handler
      end
    rescue DatabaseExpiryError => e
      logger.error(e.message, :cause => e.cause, :backtrace => e.backtrace)
      @geoip.reset_filter_handler
    end
  end

  def close
    @scheduler.every_jobs.each(&:unschedule) if @scheduler
  end

  # provide backward compatibility for LS < 7.12 which is always in offline mode
  def get_mode(database_path)
    (database_path.nil? and logstash_version >= 7.12)? :online : :offline
  end

  def database_path
    @database_path
  end

  protected
  # Resolve database path from metadata and validate with md5
  # Write current timestamp if metadata file is missing
  def setup_metadata
    metadata = get_metadata.last

    if metadata
      path = get_file_path(metadata[Column::FILENAME])
      if file_exist?(path) && (md5(path) == metadata[Column::MD5])
        @database_path = path
      end
    else
      save_timestamp
    end
  end

  # return a valid database path or default database path
  def patch_database_path(database_path)
    unless file_exist?(database_path)
      database_path = get_file_path("GeoLite2-#{@database_type}.mmdb")

      unless file_exist?(database_path)
        raise "You must specify 'database => ...' in your geoip filter (I looked for '#{database_path}')"
      end
    end

    database_path
  end

  # csv format: database_type, update_at, gz_md5, md5, filename
  def save_timestamp
    metadata = get_metadata(false)
    metadata << [@database_type, Time.now.to_i, md5(database_zip_path), md5(@database_path), database_filename]

    ::CSV.open @metadata_path, 'w' do |csv|
      metadata.each { |row| csv << row }
    end
  end

  # Call infra endpoint to get md5 of latest database and verify with metadata
  # return [has_update, server db info]
  def check_update
    uuid = get_uuid
    res = rest_client.get("#{GEOIP_ENDPOINT}?key=#{uuid}")

    all_db = JSON.parse(res.body)
    target_db = all_db.select { |info| info['name'].include?(@database_type) }.first

    metadata = get_metadata.last
    if metadata
      [metadata[Column::GZ_MD5] != target_db['md5_hash'], target_db]
    else
      [true, target_db]
    end
  end

  def download_database(server_db)
    Stud.try(3.times) do
      new_database_zip_path = get_file_path(server_db['name'].gsub(@database_type, "#{@database_type}_#{Time.now.to_i}"))
      Down.download(server_db['url'], destination: new_database_zip_path)
      raise "the new download has wrong checksum" if md5(new_database_zip_path) != server_db['md5_hash']
      new_database_zip_path
    end
  end

  def unzip(zip_path)
    database_path = zip_path[0...-3]
    Zlib::GzipReader.open(zip_path) do |gz|
      ::File.open(database_path, "wb") do |f|
        f.print gz.read
      end
    end
    database_path
  end

  # Make sure the path has usable database
  def assert_database(database_path)
    raise "failed to load database #{database_path}" unless org.logstash.filters.GeoIPFilter.validate_database(database_path)
  end

  def check_age
    metadata = get_metadata.last
    timestamp = (metadata)? metadata[Column::UPDATE_AT] : 0

    days_without_update = (Time.now.to_i - timestamp.to_i) / (24 * 60 * 60)

    case
    when days_without_update >= 30
      raise DatabaseExpiryError, "The MaxMind database has been used for more than 30 days without update. According to EULA, GeoIP plugin needs to stop in order to be compliant. Please check the network settings and allow Logstash accesses the internet to download the latest database, or switch to offline mode (:database => PATH_TO_YOUR_DATABASE) to use a self-managed database from maxmind.com"
    when days_without_update >= 25
      logger.warn("The MaxMind database has been used for #{days_without_update} days without update. Logstash will stop the GeoIP plugin in #{30 - days_without_update} days. Please check the network settings and allow Logstash accesses the internet to download the latest database ")
    end
  end

  # Give rows of metadata in default database type, or empty array
  def get_metadata(match_type = true)
    if file_exist?(@metadata_path)
      ::CSV.parse(::File.read(@metadata_path), headers: false).select do |row|
        b = row[Column::DATABASE_TYPE].eql?(@database_type)
        (match_type)? b: !b
      end
    else
      Array.new
    end
  end

  # Clean up files .mmdb, .gz which are not mentioned in metadata and not default database
  def clean_up_database
    if file_exist?(@metadata_path)
      used_filenames = ::CSV.parse(::File.read(@metadata_path), headers: false).flat_map do |row|
        [row[Column::FILENAME], row[Column::FILENAME].gsub('mmdb', 'gz')]
      end
      protected_filenames = (used_filenames + DEFAULT_DATABASE_FILENAME).uniq

      existing_filenames = ::Dir.glob(get_file_path('*.{mmdb,gz}')).map { |path| path.split("/").last }

      (existing_filenames - protected_filenames).each do |filename|
        ::File.delete(get_file_path(filename))
      end
    end
  end

  def rest_client
    @client ||= Faraday.new do |conn|
      conn.adapter :net_http
      conn.use Faraday::Response::RaiseError
    end
  end

  def get_file_path(filename)
    ::File.join(::File.expand_path("../../../../vendor/", ::File.dirname(__FILE__)), filename)
  end

  def file_exist?(path)
    !path.nil? && ::File.exist?(path)
  end

  def database_filename
    @database_path.split("/").last
  end

  def database_zip_path
    @database_path + '.gz'
  end

  def md5(file_path)
    file_exist?(file_path) ? Digest::MD5.hexdigest(::File.read(file_path)): ""
  end

  def get_uuid
    @uuid ||= ::File.read(::File.join(LogStash::SETTINGS.get("path.data"), "uuid"))
  end

  def logstash_version
    LOGSTASH_VERSION.to_f
  end

  class Column
    DATABASE_TYPE = 0
    UPDATE_AT     = 1
    GZ_MD5        = 2
    MD5           = 3
    FILENAME      = 4
  end

  class DatabaseExpiryError < StandardError
  end
end end end end