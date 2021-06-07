# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "insist"
require "logstash/filters/geoip"
require_relative 'test_helper'

describe LogStash::Filters::GeoIP do

  before(:each) do
    ::File.delete(METADATA_PATH) if ::File.exist?(METADATA_PATH)
  end

  describe "config without database path in LS >= 7.13", :aggregate_failures do
    before(:each) do
      dir_path = Stud::Temporary.directory
      File.open(dir_path + '/uuid', 'w') { |f| f.write(SecureRandom.uuid) }
      allow(LogStash::SETTINGS).to receive(:get).and_call_original
      allow(LogStash::SETTINGS).to receive(:get).with("path.data").and_return(dir_path)
    end

    let(:plugin) { LogStash::Filters::GeoIP.new("source" => "[target][ip]") }

    context "restart the plugin" do
      let(:event) { LogStash::Event.new("target" => { "ip" => "173.9.34.107" }) }
      let(:event2) { LogStash::Event.new("target" => { "ip" => "55.159.212.43" }) }

      it "should use the same database" do
        unless plugin.load_database_manager?
          logstash_path = ENV['LOGSTASH_PATH'] || '/usr/share/logstash' # docker logstash home
          stub_const('LogStash::Environment::LOGSTASH_HOME', logstash_path)
        end

        plugin.register
        plugin.filter(event)
        plugin.close
        first_dirname = get_metadata_city_database_name
        plugin.register
        plugin.filter(event2)
        plugin.close
        second_dirname = get_metadata_city_database_name

        expect(first_dirname).not_to be_nil
        expect(first_dirname).to eq(second_dirname)
        expect(File).to exist(get_file_path(first_dirname))
      end
    end
  end if MAJOR >= 8 || (MAJOR == 7 && MINOR >= 13)

  describe "config without database path in LS < 7.14" do
    context "should run in offline mode" do
      config <<-CONFIG
      filter {
        geoip {
          source => "ip"
        }
      }
      CONFIG

      sample("ip" => "173.9.34.107") do
        insist { subject.get("geoip") }.include?("ip")
        expect(::File.exist?(METADATA_PATH)).to be_falsey
      end
    end
  end if MAJOR < 7 || (MAJOR == 7 && MINOR <= 14)
end
