# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "insist"
require "logstash/filters/geoip"
require_relative 'test_helper'

describe LogStash::Filters::GeoIP do
  before(:each) do
    stub_const('LogStash::OSS', false)
    stub_const('LogStash::Filters::Geoip::DatabaseManager::GEOIP_HOST', GEOIP_STAGING_HOST)
    ::File.delete(METADATA_PATH) if ::File.exist?(METADATA_PATH)
  end

  describe "config without database path in LS >= 7.12" do
    before(:each) do
      dir_path = Stud::Temporary.directory
      File.open(dir_path + '/uuid', 'w') { |f| f.write(SecureRandom.uuid) }
      allow(LogStash::SETTINGS).to receive(:get).and_call_original
      allow(LogStash::SETTINGS).to receive(:get).with("path.data").and_return(dir_path)
    end

    let(:plugin) {
      LogStash::Filters::GeoIP.new(
        "source" => "[target][ip]",
        "target" => "target",
        "fields" => [ "city_name", "region_name" ],
        "add_tag" => "done"
      )
    }

    context "with event" do
      let(:event) { LogStash::Event.new("target" => { "ip" => "173.9.34.107" }) }

      it "should raise error if Logstash is running in OSS" do
        stub_const('LogStash::OSS', true)
        expect { plugin.register }.to raise_error /open source version/
      end
    end

    context "restart the plugin" do
      let(:event) { LogStash::Event.new("target" => { "ip" => "173.9.34.107" }) }
      let(:event2) { LogStash::Event.new("target" => { "ip" => "55.159.212.43" }) }

      it "should use the same database" do
        plugin.register
        plugin.filter(event)
        plugin.close
        first_database_name = get_metadata_database_name
        plugin.register
        plugin.filter(event2)
        plugin.close
        second_database_name = get_metadata_database_name

        expect(first_database_name).not_to be_nil
        expect(first_database_name).to eq(second_database_name)
        expect(::File.exist?(get_file_path(first_database_name))).to be_truthy
      end
    end
  end if LOGSTASH_VERSION >= '7.12'

  describe "config without database path in LS < 7.12" do
    context "should run in offline mode" do
      config <<-CONFIG
      filter {
        geoip {
          source => "ip"
        }
      }
      CONFIG

      sample("ip" => "173.9.34.107") do
        expect(subject).not_to be_nil
        expect(::File.exist?(METADATA_PATH)).to be_falsey
      end
    end
  end if LOGSTASH_VERSION < '7.12'
end
