require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/geoip"

describe LogStash::Filters::GeoIP do

  describe "defaults" do
    config <<-CONFIG
      filter {
        geoip { 
          source => "ip"
          #database => "vendor/geoip/GeoLiteCity.dat"
        }
      }
    CONFIG

    sample("ip" => "8.8.8.8") do
      insist { subject }.include?("geoip")

      expected_fields = %w(ip country_code2 country_code3 country_name
                           continent_code region_name city_name postal_code
                           latitude longitude dma_code area_code timezone
                           location )
      expected_fields.each do |f|
        insist { subject["geoip"] }.include?(f)
      end
    end

    sample("ip" => "127.0.0.1") do
      # assume geoip fails on localhost lookups
      reject { subject }.include?("geoip")
    end
  end

  describe "Specify the target" do
    config <<-CONFIG
      filter {
        geoip { 
          source => "ip"
          #database => "vendor/geoip/GeoLiteCity.dat"
          target => src_ip
        }
      }
    CONFIG

    sample("ip" => "8.8.8.8") do
      insist { subject }.include?("src_ip")

      expected_fields = %w(ip country_code2 country_code3 country_name
                           continent_code region_name city_name postal_code
                           latitude longitude dma_code area_code timezone
                           location )
      expected_fields.each do |f|
        insist { subject["src_ip"] }.include?(f)
      end
    end

    sample("ip" => "127.0.0.1") do
      # assume geoip fails on localhost lookups
      reject { subject }.include?("src_ip")
    end
  end

  describe "correct encodings with default db" do
    config <<-CONFIG
      filter {
        geoip {
          source => "ip"
        }
      }
    CONFIG
    expected_fields = %w(ip country_code2 country_code3 country_name
                           continent_code region_name city_name postal_code
                           dma_code area_code timezone)

    sample("ip" => "1.1.1.1") do
      checked = 0
      expected_fields.each do |f|
        next unless subject["geoip"][f]
        checked += 1
        insist { subject["geoip"][f].encoding } == Encoding::UTF_8
      end
      insist { checked } > 0
    end
    sample("ip" => "189.2.0.0") do
      checked = 0
      expected_fields.each do |f|
        next unless subject["geoip"][f]
        checked += 1
        insist { subject["geoip"][f].encoding } == Encoding::UTF_8
      end
      insist { checked } > 0
    end

  end

  describe "correct encodings with ASN db" do
    asndb = ::Dir.glob(::File.expand_path("../../vendor/", ::File.dirname(__FILE__))+"/GeoIPASNum*.dat").first
    config <<-CONFIG
      filter {
        geoip {
          source => "ip"
          database => "#{asndb}"
        }
      }
    CONFIG


    sample("ip" => "1.1.1.1") do
      insist { subject["geoip"]["asn"].encoding } == Encoding::UTF_8
    end
    sample("ip" => "187.2.0.0") do
      insist { subject["geoip"]["asn"].encoding } == Encoding::UTF_8
    end
    sample("ip" => "189.2.0.0") do
      insist { subject["geoip"]["asn"].encoding } == Encoding::UTF_8
    end
    sample("ip" => "161.24.0.0") do
      insist { subject["geoip"]["asn"].encoding } == Encoding::UTF_8
    end
  end

  describe "location field" do
    shared_examples_for "an event with a [geoip][location] field" do
      subject(:event) { LogStash::Event.new("message" => "8.8.8.8") }
      let(:plugin) { LogStash::Filters::GeoIP.new("source" => "message", "fields" => ["country_name", "location", "longitude"]) }

      before do
        plugin.register
        plugin.filter(event)
      end

      it "should have a location field" do
        expect(event["[geoip][location]"]).not_to(be_nil)
      end
    end

    context "when latitude field is excluded" do
      let(:fields) { ["country_name", "location", "longitude"] }
      it_behaves_like "an event with a [geoip][location] field"
    end

    context "when longitude field is excluded" do
      let(:fields) { ["country_name", "location", "latitude"] }
      it_behaves_like "an event with a [geoip][location] field"
    end

    context "when both latitude and longitude field are excluded" do
      let(:fields) { ["country_name", "location"] }
      it_behaves_like "an event with a [geoip][location] field"
    end
  end
end
