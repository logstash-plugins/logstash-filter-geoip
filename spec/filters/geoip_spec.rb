# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/geoip"

CITYDB = ::Dir.glob(::File.expand_path("../../vendor/", ::File.dirname(__FILE__))+"/GeoLite2-City.mmdb").first

describe LogStash::Filters::GeoIP do

  describe "defaults" do
    config <<-CONFIG
      filter {
        geoip {
          source => "ip"
          #database => "#{CITYDB}"
        }
      }
    CONFIG

    sample("ip" => "8.8.8.8") do
      insist { subject }.include?("geoip")

      expected_fields = %w(ip country_code2 country_code3 country_name
                           continent_code region_name city_name postal_code
                           latitude longitude dma_code timezone
                           location )
      expected_fields.each do |f|
        insist { subject["geoip"] }.include?(f)
      end
    end

    sample("ip" => "127.0.0.1") do
      # assume geoip fails on localhost lookups
      expect(subject["geoip"]).to eq({})
    end
  end

  describe "normal operations" do
    config <<-CONFIG
      filter {
        geoip {
          source => "ip"
          #database => "#{CITYDB}"
          target => src_ip
          add_tag => "done"
        }
      }
    CONFIG

    context "when specifying the target" do

      sample("ip" => "8.8.8.8") do
        expect(subject).to include("src_ip")

        expected_fields = %w(ip country_code2 country_code3 country_name
                             continent_code region_name city_name postal_code
                             latitude longitude dma_code timezone
                             location )
        expected_fields.each do |f|
          expect(subject["src_ip"]).to include(f)
        end
      end

      sample("ip" => "127.0.0.1") do
        # assume geoip fails on localhost lookups
        expect(subject["src_ip"]).to eq({})
      end
    end

    context "when specifying add_tag" do
      sample("ip" => "8.8.8.8") do
        expect(subject["tags"]).to include("done")
      end
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
                           dma_code timezone)

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

  describe "an invalid IP" do
    config <<-CONFIG
          filter {
            geoip {
              source => "ip"
              database => "#{CITYDB}"
            }
          }
        CONFIG
    describe "should not raise an error" do
      sample("ip" => "-") do
        expect{ subject }.to_not raise_error
      end

      sample("ip" => "~") do
        expect{ subject }.to_not raise_error
      end
    end

    describe "filter method outcomes" do
      let(:plugin) { LogStash::Filters::GeoIP.new("source" => "message", "add_tag" => "done", "database" => CITYDB) }
      let(:event) { LogStash::Event.new("message" => ipstring) }

      before do
        plugin.register
        plugin.filter(event)
      end

      context "when the bad IP is N/A" do
        # regression test for issue https://github.com/logstash-plugins/logstash-filter-geoip/issues/50
        let(:ipstring) { "N/A" }

        it "should set the target field to an empty hash" do
          expect(event["geoip"]).to eq({})
        end

        it "should add failure tags" do
          expect(event["tags"]).to include("_geoip_lookup_failure")
        end
      end

      context "when the bad IP is two ip comma separated" do
        # regression test for issue https://github.com/logstash-plugins/logstash-filter-geoip/issues/51
        let(:ipstring) { "123.45.67.89,61.160.232.222" }

        it "should set the target field to an empty hash" do
          expect(event["geoip"]).to eq({})
        end
      end
      
      context "when a IP is not found in the DB" do
        let(:ipstring) { "10.10.10.10" }

        it "should set the target field to an empty hash" do
          expect(event["geoip"]).to eq({})
          expect(event["tags"]).to include("_geoip_lookup_failure")
        end
      end
      
      context "when IP is IPv6 format for localhost" do
        let(:ipstring) { "::1" }

        it "should set the target field to an empty hash" do
          expect(event["geoip"]).to eq({})
        end
      end
      
      context "when IP is IPv6 format" do
        let(:ipstring) { "2607:f0d0:1002:51::4" }

        it "should set the target field to an empty hash" do
          expect(event["geoip"]).not_to be_empty
          expect(event["geoip"]["city_name"]).not_to be_nil
        end
      end
      
    end

    context "should return the correct source field in the logging message" do
      sample("ip" => "-") do
        expect(LogStash::Filters::GeoIP.logger).to receive(:error).with(anything, include(:field => "ip"))
        subject
      end
    end

  end

  describe "an invalid database" do
    config <<-CONFIG
          filter {
            geoip {
              source => "ip"
              database => "./Gemfile"
            }
          }
        CONFIG

    context "should return the correct sourcefield in the logging message" do
      sample("ip" => "8.8.8.8") do
        expect(LogStash::Filters::GeoIP.logger).to receive(:error).with(anything, include(:field => "ip"))
        expect { subject }.to raise_error
      end
    end
  end

end
