# encoding: utf-8
require 'pathname'
require "logstash/devutils/rspec/spec_helper"
require "insist"
require "logstash/filters/geoip"
require_relative 'test_helper'

describe LogStash::Filters::GeoIP do
  context "when no database_path is given" do

    let(:last_db_path_recorder) do
      Module.new do
        attr_reader :last_db_path
        def setup_filter(db_path)
          @last_db_path = db_path
          super
        end
      end
    end

    let(:plugin_config) { Hash["source" => "[source][ip]", "target" => "[target]"] }
    let(:plugin) { described_class.new(plugin_config).extend(last_db_path_recorder) }
    let(:event) { LogStash::Event.new("source" => { "ip" => "173.9.34.107" }) }

    shared_examples "event enrichment" do
      it 'enriches events' do
        plugin.register
        plugin.filter(event)

        expect(event.get("target")).to include('ip')
      end
    end

    database_management_available = (MAJOR >= 8 || (MAJOR == 7 && MINOR >= 14)) && !LogStash::OSS
    if database_management_available
      context "when geoip database management is available" do

        let(:mock_manager) do
          double('LogStash::Filters::Geoip::DatabaseManager').tap do |m|
            allow(m).to receive(:subscribe_database_path) do |db_type, explicit_path, plugin_instance|
              explicit_path || mock_managed[db_type]
            end
            allow(m).to receive(:unsubscribe_database_path).with(any_args)
          end
        end

        # The extension to this plugin that lives in Logstash core will _always_ provide a valid
        # database path, and how it does so is not the concern of this plugin. We emulate this
        # behaviour here by copying the vendored CC-licensed db's into a temporary path
        let(:mock_managed) do
          managed_path = Pathname.new(temp_data_path).join("managed", Time.now.to_i.to_s).tap(&:mkpath)

          managed_city_db_path = Pathname.new(DEFAULT_CITY_DB_PATH).basename.expand_path(managed_path).to_path
          FileUtils.cp(DEFAULT_CITY_DB_PATH, managed_city_db_path)

          managed_asn_db_path = Pathname.new(DEFAULT_ASN_DB_PATH).basename.expand_path(managed_path).to_path
          FileUtils.cp(DEFAULT_ASN_DB_PATH, managed_asn_db_path)

          {
            'City' => managed_city_db_path,
            'ASN' => managed_asn_db_path,
          }
        end

        before(:each) do
          allow_any_instance_of(described_class).to receive(:load_database_manager?).and_return(true)
          stub_const("LogStash::Filters::Geoip::DatabaseManager", double("DatabaseManager.Class", :instance => mock_manager))
        end

        let(:temp_data_path) { Stud::Temporary.directory }
        after(:each) do
          FileUtils.rm_rf(temp_data_path) if File.exist?(temp_data_path)
        end

        it "uses a managed database" do
          plugin.register
          plugin.filter(event)
          expect(plugin.last_db_path).to_not be_nil
          expect(plugin.last_db_path).to start_with(temp_data_path)
        end

        include_examples "event enrichment"
      end
    else
      context "when geoip database management is not available" do

        include_examples "event enrichment"

        it "uses a plugin-vendored database" do
          plugin.register
          expect(plugin.last_db_path).to_not be_nil
          expect(plugin.last_db_path).to include("/vendor/")
        end
      end
    end
  end
end
