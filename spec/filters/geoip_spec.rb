require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/geoip"

ASNDB = ::Dir.glob(::File.expand_path("../../vendor/", ::File.dirname(__FILE__))+"/GeoIPASNum*.dat").first
CITYDB = ::Dir.glob(::File.expand_path("../../vendor/", ::File.dirname(__FILE__))+"/GeoLiteCity*.dat").first

describe LogStash::Filters::GeoIP do

  describe "ASN db" do
    config <<-CONFIG
      filter {
        geoip {
          source => "ip"
          database => "#{ASNDB}"
        }
      }
    CONFIG

    sample("ip" => "1.1.1.1") do
      insist { subject["geoip"]["asn"] } == "Google Inc."
    end

    # avoid crashing on unsupported IPv6 addresses
    # see https://github.com/logstash-plugins/logstash-filter-geoip/issues/21
    sample("ip" => "2a02:8071:aa1:c700:7984:22fc:c8e6:f6ff") do
      reject { subject }.include?("geoip")
    end
  end

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
                             latitude longitude dma_code area_code timezone
                             location )
        expected_fields.each do |f|
          expect(subject["src_ip"]).to include(f)
        end
      end

      sample("ip" => "127.0.0.1") do
        # assume geoip fails on localhost lookups
        expect(subject).not_to include("src_ip")
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
    config <<-CONFIG
      filter {
        geoip {
          source => "ip"
          database => "#{ASNDB}"
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

  describe "an invalid IP" do
    config <<-CONFIG
          filter {
            geoip {
              source => "ip"
              database => "#{ASNDB}"
              filter_private_ips => false
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
      let(:plugin) { LogStash::Filters::GeoIP.new("source" => "message", "add_tag" => "done", "database" => ASNDB, "filter_private_ips" => false) }
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

        it "should not have added any tags" do
          expect(event["tags"]).to be_nil
        end
      end

      context "when the bad IP is two ip comma separated" do
        # regression test for issue https://github.com/logstash-plugins/logstash-filter-geoip/issues/51
        let(:ipstring) { "123.45.67.89,61.160.232.222" }
        
        it "should set the target field to an empty hash" do
          expect(event["geoip"]).to eq({})
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

  describe "multiple ips" do
    config <<-CONFIG
          filter {
            geoip {
              source => "ip"
              database => "#{ASNDB}"
              filter_private_ips => true
            }
          }
        CONFIG

    describe "filter method outcomes" do
      let(:plugin) { LogStash::Filters::GeoIP.new("source" => "message", "add_tag" => "done", "database" => ASNDB) }
      let(:event) { LogStash::Event.new("message" => ipstring) }

      before do
        plugin.register
        plugin.filter(event)
      end

      context "when multiple ips are found" do
        # regression test for issue https://github.com/logstash-plugins/logstash-filter-geoip/issues/51
        let(:ipstring) { "123.45.67.89,61.160.232.222" }

        it "should take the first public ip" do # {"number"=>"AS6619", "asn"=>"SamsungSDS Inc."}
          expect(event["geoip"]["number"]).not_to be_nil
          expect(event["geoip"]["asn"]).not_to be_nil
        end
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
        subject
      end
    end
  end

  describe "returned object identities" do
    let(:plugin) { LogStash::Filters::GeoIP.new("source" => "message") }
    let(:event) { LogStash::Event.new("message" => "8.8.8.8") }
    let(:alt_event) { LogStash::Event.new("message" => "8.8.8.8") }

    before do
      plugin.register
    end

    it "should dup the objects" do
      plugin.apply_geodata(plugin.get_geo_data(event), event)
      plugin.apply_geodata(plugin.get_geo_data(alt_event), alt_event)

      event["geoip"].each do |k,v|
        alt_v = alt_event["geoip"][k]
        expect(v).to eql(alt_v)
        unless v.is_a?(Numeric) # Numeric values can't be mutated, so this isn't an issue, its really for strings
          expect(v.object_id).not_to eql(alt_v.object_id), "Object Ids for key #{k} and v #{v}"
        end
      end
    end
  end

  describe "re-initializing thread current DB" do
    let(:plugin) { LogStash::Filters::GeoIP.new("source" => "message") }

    before do
      plugin.register
    end

    it "should initialize the DB on lookup, regardless of thread state" do
      Thread.current[plugin.threadkey] = nil
      expect {
        plugin.get_geo_data_for_ip("8.8.8.8")
      }.not_to raise_error
    end
  end
end
