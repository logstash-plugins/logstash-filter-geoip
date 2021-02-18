# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/geoip"
require_relative 'test_helper'

describe LogStash::Filters::GeoIP do

  describe "#load_database_manager?", :aggregate_failures do
    let(:plugin) { LogStash::Filters::GeoIP.new("source" => "[target][ip]") }

    before :each do
      logstash_path = ENV['LOGSTASH_PATH'] || '/usr/share/logstash' # docker logstash home
      stub_const('LogStash::Environment::LOGSTASH_HOME', logstash_path)
    end

    context "> 7.13" do
      it "should be true" do
        expect(plugin.load_database_manager?).to be_truthy
      end
    end if MAJOR >= 8 || (MAJOR == 7 && MINOR >= 13)

    context "<= 7.12" do
      it "should be false" do
        expect(plugin.load_database_manager?).to be_falsey
      end
    end if MAJOR < 7 || (MAJOR == 7 && MINOR <= 12)
  end
end
