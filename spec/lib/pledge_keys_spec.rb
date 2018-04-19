require 'pledge_keys'
require 'pledge'
require 'net/http'

require 'rails_helper'

RSpec.describe PledgeKeys do

  describe "IDevID certificate" do
    it "should be a public key" do
      b = PledgeKeys.instance.idevid_pubkey
      expect(b).to be_kind_of(OpenSSL::X509::Certificate)
    end
  end

  def cmp_pkcs_file(smime, base)
    ofile = File.join("tmp", base + ".pkcs")
    otfile = File.join("tmp", base+ ".txt")

    File.open(ofile, "w") do |f|     f.puts smime      end

    system("bin/pkcs2json #{ofile} #{otfile}")
    cmd = "diff #{otfile} spec/files/#{base}.txt"
    puts cmd
    system(cmd)
  end

  def registrar_cert
    @reg_cert ||= OpenSSL::X509::Certificate.new(File.open(Rails.root.join("spec", "files", "jrc_cert.pem"), "r"))
  end

  describe "IDevID private key" do
    it "should be a kind of private key" do
      b = PledgeKeys.instance.idevid_privkey
      expect(b).to be_kind_of(OpenSSL::PKey::PKey)
    end

    it "should pkcs sign a voucher request" do
      vr = Chariwt::VoucherRequest.new
      vr.nonce = "Dss99sBr3pNMOACe-LYY7w"
      vr.assertion = :proximity
      vr.signing_cert = PledgeKeys.instance.idevid_pubkey
      vr.serialNumber = vr.eui64_from_cert
      vr.createdOn    = '2017-09-01'.to_date
      vr.proximityRegistrarCert = registrar_cert
      smime = vr.pkcs_sign(PledgeKeys.instance.idevid_privkey)

      cmp_pkcs_file(smime, "pledge_request01")
    end

    it "should cose sign a voucher request" do
      vr = Chariwt::VoucherRequest.new
      vr.nonce = "Dss99sBrab660fCe-LYY7w"
      vr.assertion = :proximity
      vr.signing_cert = PledgeKeys.instance.idevid_pubkey
      vr.serialNumber = vr.eui64_from_cert
      vr.createdOn    = '2018-02-03'.to_date
      vr.proximityRegistrarCert = registrar_cert
      cbor = vr.cose_sign(PledgeKeys.instance.idevid_privkey)

      cmp_pkcs_file(cbor, "pledge_cbor01")
    end
  end

  describe "pledge enrollment" do

    it "should open a TLS connection to fountain" do
      client = Pledge.new
      client.jrc = "https://fountain-test.sandelman.ca"

      voucher = client.get_voucher
      pending "Likely does not run if device is no longer valid"
      expect(voucher).to_not be_nil
    end
  end

  describe "MASA public key" do
    it "should be a kind of public key" do
      b = PledgeKeys.instance.masa_cert
      expect(b).to be_kind_of(OpenSSL::X509::Certificate)
    end
  end

end
