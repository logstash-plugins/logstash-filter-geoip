# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "insist"
require "logstash/filters/geoip"
require 'logstash/plugin_mixins/ecs_compatibility_support/spec_helper'

CITYDB = ::Dir.glob(::File.expand_path("../../vendor/", ::File.dirname(__FILE__))+"/GeoLite2-City.mmdb").first
ASNDB = ::Dir.glob(::File.expand_path("../../vendor/", ::File.dirname(__FILE__))+"/GeoLite2-ASN.mmdb").first

describe LogStash::Filters::GeoIP do
  let(:options) { {} }
  let(:plugin) { LogStash::Filters::GeoIP.new(options) }

  describe "simple ip filter", :aggregate_failures do

    context "when specifying the target", :ecs_compatibility_support do
      ecs_compatibility_matrix(:disabled, :v1) do |ecs_select|

        let(:ip) { "8.8.8.8" }
        let(:event) { LogStash::Event.new("message" => ip) }
        let(:target) { "server" }
        let(:common_options) { {"source" => "message", "database" => CITYDB, "target" => target} }

        before(:each) do
          allow_any_instance_of(described_class).to receive(:ecs_compatibility).and_return(ecs_compatibility)
          plugin.register
        end

        context "with city database" do
          let(:options) { common_options }

          it "should return geo in target" do
            plugin.filter(event)

            expect( event.get ecs_select[disabled: "[#{target}][ip]", v1: "[#{target}][ip]"] ).to eq ip
            expect( event.get ecs_select[disabled: "[#{target}][country_code3]", v1: "[#{target}][country_code3]"] ).to eq 'US'
            expect( event.get ecs_select[disabled: "[#{target}][country_code2]", v1: "[#{target}][geo][country_iso_code]"] ).to eq 'US'
            expect( event.get ecs_select[disabled: "[#{target}][country_name]", v1: "[#{target}][geo][country_name]"] ).to eq 'United States'
            expect( event.get ecs_select[disabled: "[#{target}][continent_code]", v1: "[#{target}][geo][continent_code]"] ).to eq 'NA'
            expect( event.get ecs_select[disabled: "[#{target}][location][lat]", v1: "[#{target}][geo][location][lat]"] ).to eq 37.751
            expect( event.get ecs_select[disabled: "[#{target}][location][lon]", v1: "[#{target}][geo][location][lon]"] ).to eq -97.822
          end
        end


        context "with ASN database" do
          let(:options) { common_options.merge({"database" => ASNDB}) }

          it "should return geo in target" do
            plugin.filter(event)

            expect( event.get ecs_select[disabled: "[#{target}][ip]", v1: "[#{target}][ip]"] ).to eq ip
            expect( event.get ecs_select[disabled: "[#{target}][asn]", v1: "[#{target}][as][number]"] ).to eq 15169
            expect( event.get ecs_select[disabled: "[#{target}][as_org]", v1: "[#{target}][as][organization][name]"] ).to eq "Google LLC"
          end
        end

        context "with customize fields" do
          let(:fields) { ["continent_name", "timezone"] }
          let(:options) { common_options.merge({"fields" => fields}) }

          it "should return fields" do
            plugin.filter(event)

            expect( event.get ecs_select[disabled: "[#{target}][ip]", v1: "[#{target}][ip]"] ).to be_nil
            expect( event.get ecs_select[disabled: "[#{target}][continent_name]", v1: "[#{target}][geo][continent_name]"] ).to eq "North America"
            expect( event.get ecs_select[disabled: "[#{target}][timezone]", v1: "[#{target}][geo][timezone]"] ).to eq "America/Chicago"
          end
        end


      end
    end

    context "when target is unset", :ecs_compatibility_support do
      ecs_compatibility_matrix(:disabled, :v1) do |ecs_select|
        let(:event) { LogStash::Event.new("message" => "8.8.8.8") }
        let(:options) { {"source" => "message", "database" => CITYDB} }
        before(:each) do
          allow_any_instance_of(described_class).to receive(:ecs_compatibility).and_return(ecs_compatibility)
          plugin.register
        end

        it "should use default target value" do
          plugin.filter(event)

          expect( event.get ecs_select[disabled: "[geoip][country_code3]", v1: "[client][country_code3]"] ).to eq 'US'
          expect( event.get ecs_select[disabled: "[geoip][country_code2]", v1: "[client][geo][country_iso_code]"] ).to eq 'US'
        end
      end
    end

  end

end
