require 'pledge_keys'
require 'pledge'
require 'net/http'

require 'rails_helper'

RSpec.describe SmartPledge do

  describe "DPP string parsing" do
    it "should process a string from highway" do
      string = IO::read("spec/files/dpp1.txt")
      dpp
    end

    it "should decode smartpledge" do
      dc = DPPCode.new
      dc.parse_one_item("S:highway-test.example.com")
      expect(dc.smartpledge).to eq("highway-test.example.com")
    end

    it "should decode with colon in smartpledge" do
      dc = DPPCode.new
      dc.parse_one_item("S:highway-test.example.com:9884")
      expect(dc.smartpledge).to eq("highway-test.example.com:9884")
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

    it "should decode mac" do
      dc = DPPCode.new
      dc.parse_one_item("M:00163E8D519B")
      expect(dc.mac).to eq("00163E8D519B")
    end

    it "should decode key" do
      dc = DPPCode.new
      dc.parse_one_item("K:MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEujp6VXpEgkSkPFM+R5iETYQ4hTZiZDZPJKqJWJJmQ6nFC8tS6QjITod6LFZ22WrwJ4NK987wAeRNkh3XTtCD5w==")
      expect(dc.key).to be_a(OpenSSL::PKey)
    end

    it "should not break on broken base64" do
      dc = DPPCode.new
      dc.parse_one_item("K:MFkwEwYHKoZIzjAQYIKoZIzj0DAQcDQgAEujp6VXpEgkSkPFM+R5iETYQ4hTZiZDZPJKqJWJJmQ6nFC8tS6QjITod6LFZ22WrwJ4NK987wAeRNkh3XTtCD5w==")
      expect(dc.keybinary).to be_nil
    end

    it "should not break on invalid key" do
      dc = DPPCode.new
      dc.parse_one_item("K:YWJjZAYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEujp6VXpEgkSkPFM+R5iETYQ4hTZiZDZPJKqJWJJmQ6nFC8tS6QjITod6LFZ22WrwJ4NK987wAeRNkh3XTtCD5w==")
      expect(dc.keybinary).to_not be_nil
      expect(dc.key).to be_nil
    end
  end

end
