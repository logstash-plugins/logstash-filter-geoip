# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/geoip"
require_relative 'test_helper'
require 'logstash/plugin_mixins/ecs_compatibility_support/spec_helper'

CITYDB = ::Dir.glob(::File.expand_path(::File.join("..", "..", "..", "vendor", "GeoLite2-City.mmdb"), __FILE__)).first
ASNDB = ::Dir.glob(::File.expand_path(::File.join("..", "..", "..", "vendor", "GeoLite2-ASN.mmdb"), __FILE__)).first

describe LogStash::Filters::GeoIP do
  let(:options) { {} }
  let(:plugin) { LogStash::Filters::GeoIP.new(options) }

  describe "simple ip filter", :aggregate_failures do

    context "when specifying the target", :ecs_compatibility_support do
      ecs_compatibility_matrix(:disabled, :v1, :v8 => :v1) do |ecs_select|

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
            expect( event.get ecs_select[disabled: "[#{target}][country_code2]", v1: "[#{target}][geo][country_iso_code]"] ).to eq 'US'
            expect( event.get ecs_select[disabled: "[#{target}][country_name]", v1: "[#{target}][geo][country_name]"] ).to eq 'United States'
            expect( event.get ecs_select[disabled: "[#{target}][continent_code]", v1: "[#{target}][geo][continent_code]"] ).to eq 'NA'
            expect( event.get ecs_select[disabled: "[#{target}][location][lat]", v1: "[#{target}][geo][location][lat]"] ).to eq 37.751
            expect( event.get ecs_select[disabled: "[#{target}][location][lon]", v1: "[#{target}][geo][location][lon]"] ).to eq -97.822

            if ecs_select.active_mode == :disabled
              expect( event.get "[#{target}][country_code3]" ).to eq 'US'
            else
              expect( event.get "[#{target}][geo][country_code3]" ).to be_nil
              expect( event.get "[#{target}][country_code3]" ).to be_nil
            end
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

          context "with customize fields" do
            let(:fields) { ["AUTONOMOUS_SYSTEM_NUMBER"] }
            let(:options) { common_options.merge({"database" => ASNDB, "fields" => fields}) }

            it "should give asn field" do
              plugin.filter(event)

              expect( event.get ecs_select[disabled: "[#{target}][ip]", v1: "[#{target}][ip]"] ).to be_nil
              expect( event.get ecs_select[disabled: "[#{target}][as_org]", v1: "[#{target}][as][organization][name]"] ).to be_nil

              expect( event.get ecs_select[disabled: "[#{target}][asn]", v1: "[#{target}][as][number]"] ).to eq 15169
            end
          end
        end

        context "with customize fields" do
          context "continent_name and timezone" do
            let(:fields) { ["continent_name", "timezone"] }
            let(:options) { common_options.merge({"fields" => fields}) }

            it "should return fields in UTF8" do
              plugin.filter(event)

              expect( event.get ecs_select[disabled: "[#{target}][ip]", v1: "[#{target}][ip]"] ).to be_nil
              expect( event.get ecs_select[disabled: "[#{target}][country_code2]", v1: "[#{target}][geo][country_iso_code]"] ).to be_nil
              expect( event.get ecs_select[disabled: "[#{target}][country_name]", v1: "[#{target}][geo][country_name]"] ).to be_nil
              expect( event.get ecs_select[disabled: "[#{target}][continent_code]", v1: "[#{target}][geo][continent_code]"] ).to be_nil
              expect( event.get ecs_select[disabled: "[#{target}][location][lat]", v1: "[#{target}][geo][location][lat]"] ).to be_nil
              expect( event.get ecs_select[disabled: "[#{target}][location][lon]", v1: "[#{target}][geo][location][lon]"] ).to be_nil

              continent_name = event.get ecs_select[disabled: "[#{target}][continent_name]", v1: "[#{target}][geo][continent_name]"]
              timezone = event.get ecs_select[disabled: "[#{target}][timezone]", v1: "[#{target}][geo][timezone]"]
              expect( continent_name ).to eq "North America"
              expect( timezone ).to eq "America/Chicago"
              expect( continent_name.encoding ).to eq Encoding::UTF_8
              expect( timezone.encoding ).to eq Encoding::UTF_8
            end
          end

          context "location" do
            shared_examples "provide location, lat and lon" do
              it "should return location, lat and lon" do
                plugin.filter(event)

                expect( event.get ecs_select[disabled: "[#{target}][ip]", v1: "[#{target}][ip]"] ).to be_nil
                expect( event.get ecs_select[disabled: "[#{target}][country_code2]", v1: "[#{target}][geo][country_iso_code]"] ).to be_nil
                expect( event.get ecs_select[disabled: "[#{target}][country_name]", v1: "[#{target}][geo][country_name]"] ).to be_nil
                expect( event.get ecs_select[disabled: "[#{target}][continent_code]", v1: "[#{target}][geo][continent_code]"] ).to be_nil
                expect( event.get ecs_select[disabled: "[#{target}][continent_name]", v1: "[#{target}][geo][continent_name]"] ).to be_nil
                expect( event.get ecs_select[disabled: "[#{target}][timezone]", v1: "[#{target}][geo][timezone]"] ).to be_nil

                expect( event.get ecs_select[disabled: "[#{target}][location][lat]", v1: "[#{target}][geo][location][lat]"] ).not_to be_nil
                expect( event.get ecs_select[disabled: "[#{target}][location][lon]", v1: "[#{target}][geo][location][lon]"] ).not_to be_nil
              end
            end

            context "location and longitude" do
              let(:fields) { ["location", "longitude"] }
              let(:options) { common_options.merge({"fields" => fields}) }
              it_behaves_like "provide location, lat and lon"
            end

            context "location and latitude" do
              let(:fields) { ["location", "latitude"] }
              let(:options) { common_options.merge({"fields" => fields}) }
              it_behaves_like "provide location, lat and lon"
            end
          end

          context "continent_code and IP is IPv6 format" do
            let(:ip) { "2607:f0d0:1002:51::4" }
            let(:fields) { ["continent_code", "ip"] }
            let(:options) { common_options.merge({"fields" => fields}) }

            it "should return fields" do
              plugin.filter(event)

              expect( event.get ecs_select[disabled: "[#{target}][country_code2]", v1: "[#{target}][geo][country_iso_code]"] ).to be_nil
              expect( event.get ecs_select[disabled: "[#{target}][country_name]", v1: "[#{target}][geo][country_name]"] ).to be_nil
              expect( event.get ecs_select[disabled: "[#{target}][continent_name]", v1: "[#{target}][geo][continent_name]"] ).to be_nil
              expect( event.get ecs_select[disabled: "[#{target}][location][lat]", v1: "[#{target}][geo][location][lat]"] ).to be_nil
              expect( event.get ecs_select[disabled: "[#{target}][location][lon]", v1: "[#{target}][geo][location][lon]"] ).to be_nil
              expect( event.get ecs_select[disabled: "[#{target}][timezone]", v1: "[#{target}][geo][timezone]"] ).to be_nil

              expect( event.get ecs_select[disabled: "[#{target}][ip]", v1: "[#{target}][ip]"] ).to eq("2607:f0d0:1002:51:0:0:0:4")
              expect( event.get ecs_select[disabled: "[#{target}][continent_code]", v1: "[#{target}][geo][continent_code]"] ).to eq("NA")
            end
          end
        end
      end
    end

    context "setup target field" do
      let(:ip) { "8.8.8.8" }
      let(:event) { LogStash::Event.new("message" => ip) }
      let(:common_options) { {"source" => "message", "database" => CITYDB} }

      context "ECS disabled" do
        before do
          allow_any_instance_of(described_class).to receive(:ecs_compatibility).and_return(:disabled)
          plugin.register
          plugin.filter(event)
        end

        context "`target` is unset" do
          let(:options) { common_options }
          it "should use 'geoip'" do
            expect( event.get "[geoip][ip]" ).to eq ip
          end
        end

        context "`target` is set" do
          let(:target) { 'host' }
          let(:options) { common_options.merge({"target" => target}) }
          it "should use `target`" do
            expect( event.get "[#{target}][ip]" ).to eq ip
          end
        end
      end

      context "ECS mode" do
        before do
          allow_any_instance_of(described_class).to receive(:ecs_compatibility).and_return(:v1)
        end

        context "`target` is unset" do

          context "`source` end with [ip]" do
            let(:event) { LogStash::Event.new("host" => {"ip" => ip}) }
            let(:options) { common_options.merge({"source" => "[host][ip]"}) }

            it "should use source's parent as target" do
              plugin.register
              plugin.filter(event)
              expect( event.get "[host][geo][country_iso_code]" ).to eq 'US'
            end
          end

          context "`source` end with [ip] but `target` does not match ECS template" do
            let(:event) { LogStash::Event.new("hostname" => {"ip" => ip}) }
            let(:options) { common_options.merge({"source" => "[hostname][ip]"}) }

            it "should use source's parent as target with warning" do
              expect(plugin.logger).to receive(:warn).with(/ECS expect `target`/)
              plugin.register
              plugin.filter(event)
              expect( event.get "[hostname][geo][country_iso_code]" ).to eq 'US'
            end
          end

          context "`source` == [ip]" do
            let(:event) { LogStash::Event.new("ip" => ip) }
            let(:options) { common_options.merge({"source" => "[ip]"}) }

            it "should raise error to require `target`" do
              expect { plugin.register }.to raise_error LogStash::ConfigurationError, /requires a `target`/
            end
          end

          context "`source` not end with [ip]" do
            let(:event) { LogStash::Event.new("host_ip" => ip) }
            let(:options) { common_options.merge({"source" => "host_ip"}) }

            it "should raise error to require `target`" do
              expect { plugin.register }.to raise_error LogStash::ConfigurationError, /requires a `target`/
            end
          end
        end

        context "`target` is set" do
          let(:event) { LogStash::Event.new("client" => {"ip" => ip}) }
          let(:options) { common_options.merge({"source" => "[client][ip]", "target" => target}) }

          context "`target` matches ECS template" do
            let(:target) { 'host' }

            it "should use `target`" do
              plugin.register
              plugin.filter(event)
              expect( event.get "[#{target}][geo][country_iso_code]" ).to eq 'US'
            end
          end

          context "`target` in canonical field reference syntax matches ECS template" do
            let(:target) { '[host]' }

            it "should normalize and use `target`" do
              expect(plugin.logger).to receive(:warn).never
              plugin.register
              plugin.filter(event)
              expect( event.get "[host][geo][country_iso_code]" ).to eq 'US'
            end
          end

          context "`target` does not match ECS template" do
            let(:target) { 'host_ip' }

            it "should use `target` with warning" do
              expect(plugin.logger).to receive(:warn).with(/ECS expect `target`/)
              plugin.register
              plugin.filter(event)
              expect( event.get "[#{target}][geo][country_iso_code]" ).to eq 'US'
            end
          end
        end
      end
    end

  end
end
