# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "insist"
require "logstash/filters/geoip"

CITYDB = ::Dir.glob(::File.expand_path(::File.join("..", "..", "..", "vendor", "GeoLite2-City.mmdb"), __FILE__)).first
ASNDB = ::Dir.glob(::File.expand_path(::File.join("..", "..", "..", "vendor", "GeoLite2-ASN.mmdb"), __FILE__)).first


describe LogStash::Filters::GeoIP do
  shared_examples "invalid empty IP" do
    it "should not give target field" do
      expect(event.get(target)).to be_nil
      expect(event.get("tags")).to include("_geoip_lookup_failure")
    end
  end

  shared_examples "invalid string IP" do
    it "should give empty hash in target field" do
      expect(event.get(target)).to eq({})
      expect(event.get("tags")).to include("_geoip_lookup_failure")
    end
  end

  let(:target) { "server" }

  describe "invalid IP" do
    let(:ip) { "173.9.34.107" }
    let(:event) { LogStash::Event.new("client" => { "ip" => ip } ) }
    let(:plugin) {
      LogStash::Filters::GeoIP.new(
        "source" => "[client][ip]",
        "target" => target,
        "fields" => %w[country_name continent_code],
        "database" => CITYDB
      )
    }

    before do
      plugin.register
      plugin.filter(event)
    end

    context "when ip is 127.0.0.1" do
      let(:ip) { "127.0.0.1" }
      it "should give empty hash" do
        expect(event.get(target)).to eq({})
      end
    end

    context "when ip is empty string" do
      let(:ip) { "" }
      it_behaves_like "invalid empty IP"
    end

    context "when ip is space" do
      let(:ip) { "      " }
      it_behaves_like "invalid empty IP"
    end

    context "when ip is dash" do
      let(:ip) { "-" }
      it_behaves_like "invalid string IP"
    end

    context "when ip is N/A" do
      let(:ip) { "N/A" }
      it_behaves_like "invalid string IP"
    end

    context "when ip is two ip comma separated" do
      let(:ip) { "123.45.67.89,61.160.232.222" }
      it_behaves_like "invalid string IP"
    end

    context "when ip is not found in the DB" do
      let(:ip) { "0.0.0.0" }
      it_behaves_like "invalid string IP"
    end

    context "when ip is IPv6 format for localhost" do
      let(:ip) { "::1" }
      it_behaves_like "invalid string IP"
    end
  end

  describe "database path is empty" do
    let(:plugin) { LogStash::Filters::GeoIP.new("source" => "message", "target" => target) }
    let(:event) { LogStash::Event.new("message" => "8.8.8.8") }

    context "when database manager give nil database path" do
      it "should tag expired database" do
        expect(plugin).to receive(:select_database_path).and_return(nil)

        plugin.register
        plugin.filter(event)

        expect(event.get("tags")).to include("_geoip_expired_database")
      end
    end
  end

  describe "database path is an invalid database file" do
    config <<-CONFIG
          filter {
            geoip {
              source => "ip"
              target => "geo"
              database => "./Gemfile"
            }
          }
        CONFIG

    context "should return the correct sourcefield in the logging message" do
      sample("ip" => "8.8.8.8") do
        expect { subject }.to raise_error(java.lang.IllegalArgumentException, "The database provided is invalid or corrupted.")
      end
    end
  end

end
