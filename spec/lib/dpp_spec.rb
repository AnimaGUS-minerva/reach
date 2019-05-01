require 'pledge_keys'
require 'pledge'
require 'net/http'

require 'rails_helper'

RSpec.describe DPPCode do

  describe "DPP string parsing" do
    it "should process a string from highway" do
      string = IO::read("spec/files/dpp1.txt")
      dc = DPPCode.new(string)
      expect(dc.smarkaklink).to eq("highway-test.example.com:9443")
      expect(dc.llv6).to eq("02163EFEFF8D519B")
      expect(dc.mac).to eq("00163E8D519B")
      expect(dc.key).to be_a(OpenSSL::PKey::EC)
      expect(dc.essid).to eq("SHG3CE618")

      expect(dc.ecdsa_key).to be_a(ECDSA::Point)
    end

    it "should decode smarkaklink" do
      dc = DPPCode.new
      dc.parse_one_item("S:highway-test.example.com")
      expect(dc.smarkaklink).to eq("highway-test.example.com")
    end

    it "should decode with colon in smarkaklink" do
      dc = DPPCode.new
      dc.parse_one_item("S:highway-test.example.com:9884")
      expect(dc.smarkaklink).to eq("highway-test.example.com:9884")
    end

    it "should find MASA URL from iauthority" do
      dc = DPPCode.new(IO::read("spec/files/dpp1.txt"))

      expect(dc.smarkaklink_enroll_url.to_s).to eq("https://highway-test.example.com:9443/.well-known/est/smarkaklink")
    end

    it "should decode essid" do
      dc = DPPCode.new
      dc.parse_one_item("E:blahblah1")
      expect(dc.essid).to eq("blahblah1")
    end

    it "should decode llv6" do
      dc = DPPCode.new
      dc.parse_one_item("L:02163EFEFF8D519B")
      expect(dc.llv6).to eq("02163EFEFF8D519B")
    end

    it "should decode llv6 to https" do
      dc = DPPCode.new
      dc.parse_one_item("L:02163EFEFF8D519B")
      expect(dc.llv6_as_iauthority).to eq("[fe80::216:3efe:ff8d:519b]")
    end

    it "should decode mac" do
      dc = DPPCode.new
      dc.parse_one_item("M:00163E8D519B")
      expect(dc.mac).to eq("00163E8D519B")
    end

    it "should decode key" do
      dc = DPPCode.new
      dc.parse_one_item("K:MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEujp6VXpEgkSkPFM+R5iETYQ4hTZiZDZPJKqJWJJmQ6nFC8tS6QjITod6LFZ22WrwJ4NK987wAeRNkh3XTtCD5w==")
      expect(dc.key).to be_a(OpenSSL::PKey::EC)
    end

    it "should not break on broken base64" do
      dc = DPPCode.new
      expect {
        dc.parse_one_item("K:MFkwEwYHKoZI$$__=QYIK=oZIzj0DAQcDQgAEujp6VXpEgkSkPFM+R5iETYQ4hTZiZDZPJKqJWJJmQ6nFC8tS6QjITod6LFZ22WrwJ4NK987wAeRNkh3XTtCD5w==")
      }.to raise_error(DPPCode::DPPKeyError)
      expect(dc.keybinary).to be_nil
    end

    it "should not break on invalid key" do
      dc = DPPCode.new
      expect {
        dc.parse_one_item("K:YWJjZAYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEujp6VXpEgkSkPFM+R5iETYQ4hTZiZDZPJKqJWJJmQ6nFC8tS6QjITod6LFZ22WrwJ4NK987wAeRNkh3XTtCD5w==")
      }.to raise_error(DPPCode::DPPKeyError)
    end
  end

end
