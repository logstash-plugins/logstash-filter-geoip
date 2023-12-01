# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/geoip"
require_relative 'test_helper'

describe LogStash::Filters::GeoIP do

  describe "database path", :aggregate_failures do
    let(:plugin) { LogStash::Filters::GeoIP.new("source" => "[target][ip]", "database" => DEFAULT_ASN_DB_PATH) }

    before :each do
      logstash_path = ENV['LOGSTASH_PATH'] || '/usr/share/logstash' # docker logstash home
      stub_const('LogStash::Environment::LOGSTASH_HOME', logstash_path)
    end

    context "select_database_path with static path" do
      it "should be the assigned path" do
        expect(plugin.select_database_path).to eql(DEFAULT_ASN_DB_PATH)
      end
    end

    shared_examples "with database manager" do
      it "load_database_manager? should be true" do
        expect(plugin.load_database_manager?).to be_truthy
      end
    end

    shared_examples "without database manager" do
      it "load_database_manager? should be false" do
        expect(plugin.load_database_manager?).to be_falsey
      end

      describe "select_database_path without path setting" do
        let(:plugin) { LogStash::Filters::GeoIP.new("source" => "[target][ip]") }

        it "should be default" do
          expect(plugin.select_database_path).to eql(DEFAULT_CITY_DB_PATH)
        end
      end
    end

    if MAJOR >= 8 || (MAJOR == 7 && MINOR >= 14)
      context "Logstash >= 7.14" do
        if LogStash::OSS
          context "OSS-only" do
            include_examples "without database manager"
          end
        else
          context "default distro" do
            include_examples "with database manager"
          end
        end
      end
    else
      describe "Logstash < 7.14" do
        include_examples "without database manager"
      end
    end
  end
end
