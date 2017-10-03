require 'pledge_keys'

RSpec.describe PledgeKeys do

  describe "IDevID public key" do
    it "should be a public key" do
      b = PledgeKeys.instance.idevid_pubkey
      expect(b).to be_kind_of(OpenSSL::X509::Certificate)
    end
  end

  describe "IDevID private key" do
    it "should be a kind of private key" do
      b = PledgeKeys.instance.idevid_privkey
      expect(b).to be_kind_of(OpenSSL::PKey::PKey)
    end
  end

  describe "MASA public key" do
    it "should be a kind of public key" do
      b = PledgeKeys.instance.masa_cert
      expect(b).to be_kind_of(OpenSSL::X509::Certificate)
    end
  end


end
