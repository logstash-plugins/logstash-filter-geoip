require "logstash/filters/geoip/database_manager"
require "logstash/filters/geoip"
require "digest"
require_relative 'test_helper'

module LogStash module Filters module Geoip
  RSpec.configure do |c|
    c.define_derived_metadata do |meta|
      meta[:aggregate_failures] = true
    end
  end

  describe DatabaseManager do
    let(:mock_geoip_plugin)  { double("geoip_plugin") }
    let(:db_manager) do
      manager = DatabaseManager.new(mock_geoip_plugin, DEFAULT_CITY_DB_PATH, "City")
      manager.instance_variable_set(:@metadata_path, Stud::Temporary.file.path)
      manager
    end
    let(:temp_metadata_path) { db_manager.instance_variable_get(:@metadata_path) }
    let(:logger) { double("Logger") }

    context "patch database" do
      it "use CC license database as default" do
        path = db_manager.send(:patch_database_path, "")
        expect(path).to eq(DEFAULT_CITY_DB_PATH)
      end

      it "failed when default database is missing" do
        expect(db_manager).to receive(:file_exist?).and_return(false, false)
        expect { db_manager.send(:patch_database_path, "") }.to raise_error /I looked for/
      end
    end

    context "get metadata" do
      it "return metadata" do
        write_temp_metadata(temp_metadata_path, city2_metadata)

        city = db_manager.send(:get_metadata)
        expect(city.size).to eq(2)

        asn = db_manager.send(:get_metadata, false)
        expect(asn.size).to eq(1)
      end

      it "return empty array when file is missing" do
        metadata = db_manager.send(:get_metadata)
        expect(metadata.size).to eq(0)
      end

      it "return empty array when an empty file exist" do
        FileUtils.touch(temp_metadata_path)

        metadata = db_manager.send(:get_metadata)
        expect(metadata.size).to eq(0)
      end
    end

    context "save timestamp" do
      it "write the current time" do
        db_manager.send(:save_timestamp)

        metadata = db_manager.send(:get_metadata)
        past = metadata.last[DatabaseManager::Column::UPDATE_AT]
        expect(Time.now.to_i - past.to_i).to be < 100
      end
    end

    context "setup metadata" do
      it "create metadata when file is missing" do
        db_manager.send(:setup_metadata)
        expect(::File.exist?(temp_metadata_path)).to be_truthy
      end

      it "use the database_path in metadata" do
        write_temp_metadata(temp_metadata_path, city2_metadata)
        copy_city_database(SECOND_CITY_DB_NAME)

        db_manager.send(:setup_metadata)
        expect(db_manager.instance_variable_get(:@database_path)).to match /#{SECOND_CITY_DB_NAME}/
      end

      it "ignore database_path in metadata if md5 does not match" do
        write_temp_metadata(temp_metadata_path, ["City","","","INVALID_MD5",SECOND_CITY_DB_NAME])
        copy_city_database(SECOND_CITY_DB_NAME)

        db_manager.send(:setup_metadata)
        expect(db_manager.instance_variable_get(:@database_path)).to match /#{DEFAULT_CITY_DB_NAME}/
      end
    end

    context "rest client" do
      it "can call endpoint" do
        conn = db_manager.send(:rest_client)
        res = conn.get("#{GEOIP_STAGING_ENDPOINT}?key=#{SecureRandom.uuid}")
        expect(res.status).to eq(200)
      end

      it "should raise error when endpoint response 4xx" do
        conn = db_manager.send(:rest_client)
        expect { conn.get("#{GEOIP_STAGING_HOST}?key=#{SecureRandom.uuid}") }.to raise_error /404/
      end
    end

    context "check update" do
      before(:each) do
        expect(db_manager).to receive(:get_uuid).and_return(SecureRandom.uuid)
        mock_resp = double("geoip_endpoint", :body => ::File.read("spec/fixtures/normal_resp.json"), :status => 200)
        allow(db_manager).to receive_message_chain("rest_client.get").and_return(mock_resp)
      end

      it "should return update boolean and db info when md5 does not match" do
        has_update, info = db_manager.send(:check_update)
        expect(has_update).to be_truthy
        expect(info).to have_key("md5_hash")
        expect(info).to have_key("name")
        expect(info).to have_key("provider")
        expect(info).to have_key("updated")
        expect(info).to have_key("url")
        expect(info["name"]).to include("City")
      end

      it "should return false when md5 is the same" do
        expect(db_manager).to receive(:get_metadata).and_return([["City",1610366455,"4013dc17343af52a841bca2a8bad7e5e","82945494bdf513f039b3026865d07f04","GeoLite2-City.mmdb"]])

        has_update, info = db_manager.send(:check_update)
        expect(has_update).to be_falsey
      end

      it "should return true when md5 does not match" do
        expect(db_manager).to receive(:get_metadata).and_return([["City",1610366455,"bca2a8bad7e5e4013dc17343af52a841","82945494bdf513f039b3026865d07f04","GeoLite2-City.mmdb"]])

        has_update, info = db_manager.send(:check_update)
        expect(has_update).to be_truthy
      end
    end

    context "md5" do
      it "return md5 if file exists" do
        str = db_manager.send(:md5, DEFAULT_CITY_DB_PATH)
        expect(str).not_to eq("")
        expect(str).not_to be_nil
      end

      it "return empty str if file not exists" do
        file = Stud::Temporary.file.path + "/invalid"
        str = db_manager.send(:md5, file)
        expect(str).to eq("")
      end
    end

    context "download database" do
      let(:db_info) do
        {
          "md5_hash" => md5_hash,
          "name" => filename,
          "provider" => "maxmind",
          "updated" => 1609891257,
          "url" => "https://github.com/logstash-plugins/logstash-filter-geoip/archive/master.zip"
        }
      end
      let(:md5_hash) { SecureRandom.hex }
      let(:filename) { "GeoLite#{rand(1000)}-City"}

      it "should raise error if md5 does not match" do
        allow(Down).to receive(:download)
        expect{ db_manager.send(:download_database, db_info) }.to raise_error /wrong checksum/
      end

      it "should download file and return zip path" do
        expect(db_manager).to receive(:md5).and_return(md5_hash)

        path = db_manager.send(:download_database, db_info)
        expect(path).to match /#{filename}/
        expect(::File.exist?(path)).to be_truthy
      end
    end

    context "unzip" do
      before(:each) do
        file_path = "spec/fixtures/sample"
        ::File.delete(file_path) if ::File.exist?(file_path)
      end

      it "gz file" do
        path = "spec/fixtures/sample.gz"
        unzip_path = db_manager.send(:unzip, path)
        expect(::File.exist?(unzip_path)).to be_truthy
      end
    end

    context "assert database" do
      it "should raise error if file is invalid" do
        expect{ db_manager.send(:assert_database, "Gemfile") }.to raise_error /failed to load database/
      end

      it "should pass validation" do
        expect(db_manager.send(:assert_database, DEFAULT_CITY_DB_PATH)).to be_nil
      end
    end

    context "check age" do
      it "should raise error when 30 days has passed" do
        write_temp_metadata(temp_metadata_path, ["City", (Time.now - (60 * 60 * 24 * 33)).to_i, "",md5(DEFAULT_CITY_DB_PATH),DEFAULT_CITY_DB_NAME])

        expect{ db_manager.send(:check_age) }.to raise_error /be compliant/
      end

      it "should give warning after 25 days" do
        write_temp_metadata(temp_metadata_path, ["City", (Time.now - (60 * 60 * 24 * 25)).to_i, "",md5(DEFAULT_CITY_DB_PATH),DEFAULT_CITY_DB_NAME])
        expect(mock_geoip_plugin).to receive(:reset_filter_handler).never
        expect(DatabaseManager).to receive(:logger).and_return(logger)
        expect(logger).to receive(:warn)

        db_manager.send(:check_age)
      end
    end

    context "execute download check" do
      it "should be false if no update" do
        expect(db_manager).to receive(:check_update).and_return([false, {}])
        allow(db_manager).to receive(:save_timestamp)

        expect(db_manager.send(:execute_download_check)).to be_falsey
      end

      it "should return true if no update" do
        expect(db_manager).to receive(:check_update).and_return([true, {}])
        allow(db_manager).to receive(:download_database)
        allow(db_manager).to receive(:unzip)
        allow(db_manager).to receive(:assert_database)
        allow(db_manager).to receive(:save_timestamp)

        expect(db_manager.send(:execute_download_check)).to be_truthy
      end

      it "should raise error when 30 days has passed" do
        allow(db_manager).to receive(:check_update).and_raise("boom")
        write_temp_metadata(temp_metadata_path, ["City", (Time.now - (60 * 60 * 24 * 33)).to_i, "",md5(DEFAULT_CITY_DB_PATH),DEFAULT_CITY_DB_NAME])

        expect{ db_manager.send(:execute_download_check) }.to raise_error /be compliant/
      end


      it "should return false when 25 days has passed" do
        allow(db_manager).to receive(:check_update).and_raise("boom")
        expect(DatabaseManager).to receive(:logger).twice.and_return(logger)
        expect(logger).to receive(:error)
        write_temp_metadata(temp_metadata_path, ["City", (Time.now - (60 * 60 * 24 * 25)).to_i, "",md5(DEFAULT_CITY_DB_PATH),DEFAULT_CITY_DB_NAME])
        expect(logger).to receive(:warn)

        expect(db_manager.send(:execute_download_check)).to be_falsey
      end
    end

    context "scheduler call" do
      it "should call plugin reset when raise error and last update > 30 days" do
        allow(db_manager).to receive(:get_uuid).and_raise("boom")
        allow(db_manager).to receive(:get_metadata).and_return([["City",0,"","",DEFAULT_CITY_DB_NAME]])
        expect(mock_geoip_plugin).to receive(:reset_filter_handler)
        db_manager.send(:call, nil, nil)
      end

      it "should not call plugin setup when database is up to date" do
        allow(db_manager).to receive(:check_update).and_return([false, nil])
        allow(mock_geoip_plugin).to receive(:setup_filter_handler).never
        db_manager.send(:call, nil, nil)
      end
    end

    context "clean up database" do
      let(:asn00) { get_file_path("GeoLite2-ASN_000000000.mmdb") }
      let(:asn00gz) { get_file_path("GeoLite2-ASN_000000000.gz") }
      let(:city00) { get_file_path("GeoLite2-City_000000000.mmdb") }
      let(:city00gz) { get_file_path("GeoLite2-City_000000000.gz") }
      let(:city44) { get_file_path("GeoLite2-City_4444444444.mmdb") }
      let(:city44gz) { get_file_path("GeoLite2-City_4444444444.gz") }

      before(:each) do
        [asn00, asn00gz, city00, city00gz, city44, city44gz].each { |file_path| ::File.delete(file_path) if ::File.exist?(file_path) }
      end

      it "should not delete when metadata file doesn't exist" do
        ::File.delete(temp_metadata_path)
        allow(::CSV).to receive(:parse).never

        db_manager.send(:clean_up_database)
      end

      it "should delete file which is not in metadata" do
        [asn00, asn00gz, city00, city00gz, city44, city44gz].each { |file_path| FileUtils.touch(file_path) }
        write_temp_metadata(temp_metadata_path, ["City",0,"",md5(DEFAULT_CITY_DB_PATH),"GeoLite2-City_4444444444.mmdb"])

        db_manager.send(:clean_up_database)
        [asn00, asn00gz, city00, city00gz].each { |file_path| expect(::File.exist?(file_path)).to be_falsey }
        [DEFAULT_CITY_DB_PATH, DEFAULT_ASN_DB_PATH, city44, city44gz].each { |file_path| expect(::File.exist?(file_path)).to be_truthy }
      end

      it "should keep the default database" do
        CSV.open temp_metadata_path, 'w' do |csv|
          csv << ["City",0,"",md5(DEFAULT_CITY_DB_PATH),"GeoLite2-City_4444444444.mmdb"]
        end

        db_manager.send(:clean_up_database)
        [DEFAULT_CITY_DB_PATH, DEFAULT_ASN_DB_PATH].each { |file_path| expect(::File.exist?(file_path)).to be_truthy }
      end
    end

    context "get mode" do
      it "should be online if LS >= 7.12" do
        stub_const('LOGSTASH_VERSION', '8.0')
        expect(db_manager.send(:get_mode, nil)).to be_eql(:online)
      end

      it "should be online if LS < 7.12" do
        stub_const('LOGSTASH_VERSION', '7.11')
        expect(db_manager.send(:get_mode, nil)).to be_eql(:offline)
      end
    end
  end
end end end