require 'pledge_keys'
require 'pledge'
require 'net/http'

require 'rails_helper'

RSpec.describe PledgeKeys do

  before(:each) do
    #puts "TEST: #{x.description}"
    #system("sha256sum spec/files/product/00-D0-E5-F2-00-01/device.crt")
    PledgeKeys.instance = nil
    PledgeKeys.instance.product_id = "spec/files/product/00-D0-E5-F2-00-01"
  end

  def temporary_key
    ECDSA::Format::IntegerOctetString.decode(["20DB1328B01EBB78122CE86D5B1A3A097EC44EAC603FD5F60108EDF98EA81393"].pack("H*"))
  end

  describe "IDevID certificate" do
    it "should be a public key" do
      b = PledgeKeys.instance.idevid_pubkey
      expect(b).to be_kind_of(OpenSSL::X509::Certificate)
    end
  end

  def cmp_pkcs_file(smime, base)
    ofile = File.join("tmp", base + ".pkcs")
    otfile = File.join("tmp", base+ ".txt")

    File.open(ofile, "wb") do |f|     f.puts smime      end

    system("bin/pkcs2json #{ofile} #{otfile}")
    cmd = "diff #{otfile} spec/files/#{base}.txt"
    puts cmd
    system(cmd)
  end

  def cmp_cbor_file(cbor, base)
    ofile = File.join("tmp", base + ".cbor")
    otfile = File.join("tmp", base+ ".txt")

    File.open(ofile, "wb") {|f| f.write cbor }

    system("cbor2diag.rb #{ofile} >#{otfile}")
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

      expect(cmp_pkcs_file(smime, "pledge_request01")).to be true
    end

    it "should cose sign a voucher request" do
      vr = Chariwt::VoucherRequest.new
      vr.nonce = "Dss99sBrab660fCe-LYY7w"
      vr.assertion = :proximity
      vr.signing_cert = PledgeKeys.instance.idevid_pubkey
      vr.serialNumber = vr.eui64_from_cert
      vr.createdOn    = '2018-02-03'.to_date
      vr.proximityRegistrarCert = registrar_cert
      cbor = vr.cose_sign(PledgeKeys.instance.idevid_privkey,
                          ECDSA::Group::Nistp256,
                          temporary_key)

      expect(cmp_cbor_file(cbor, "pledge_cbor01")).to be true
    end
  end

  describe "pledge enrollment" do

    it "should open a TLS connection to fountain" do
      client = Pledge.new
      client.jrc = "https://fountain-test.sandelman.ca"

      pending "requires fountain to be running"
      voucher = nil
      #voucher = client.get_voucher
      expect(voucher).to_not be_nil
    end

    def highwaytest_clientcert_almec_f20001
      @highwaytest_clientcert_almec      ||= OpenSSL::X509::Certificate.new(IO::read("spec/files/product/00-D0-E5-F2-00-01/device.crt"))
    end

    def highwaytest_clientcert_almec_f20001_priv
      @highwaytest_clientcert_almec_priv ||= OpenSSL::PKey.read(IO::read("spec/files/product/00-D0-E5-F2-00-01/key.pem"))
    end

    def highwaytest_bulb1_020020
      @highwaytest_bulb1_020020 ||= OpenSSL::X509::Certificate.new(IO::read("spec/files/product/00-D0-E5-02-00-20/device.crt"))
    end

    def highwaytest_bulb1_020020_priv
      @highwaytest_bulb1_020020_priv ||= OpenSSL::PKey.read(IO::read("spec/files/product/00-D0-E5-02-00-20/key.pem"))
    end

    it "should process a CSR attributes, creating a CSR for bulb1" do
      serial_number = "00-D0-E5-F2-00-01"
      PledgeKeys.instance.product_id = "spec/files/product/#{serial_number}"

      client = Pledge.new

      csrattr_str = IO::binread("spec/files/csr_bulb1.der")
      ca = CSRAttributes.from_der(csrattr_str)

      rfc822Name = ca.find_rfc822Name
      expect(rfc822Name).to include("acp.example.com")

      # now create a CSR attribute with the specified name.
      csr = client.build_csr(rfc822Name)
      expect(csr.subject.to_s).to include(serial_number)
      #expect(csr.subject.to_s).to include("00-D0-E5-03-00-03")

      File.open("tmp/csr_bulb1.csr", "wb") do |f| f.syswrite csr.to_der end
      expect(csr.verify(csr.public_key)).to be true
    end

    def florean_bulb03
      @florean_bulb03 ||= OpenSSL::X509::Certificate.new(IO::read("spec/files/product/00-D0-E5-03-00-03/device.crt"))
    end
    def florean_bulb03_priv
      @florean_bulb03_priv ||= OpenSSL::PKey.read(IO::read("spec/files/product/00-D0-E5-03-00-03/key.pem"))
    end

    it "should find a serial number from the IDevID certificate" do
      PledgeKeys.instance.product_id = "spec/files/product/00-D0-E5-03-00-03"
      expect(PledgeKeys.instance.hunt_for_serial_number).to eq("00-D0-E5-03-00-03")
    end

    it "should process a CSR attributes, creating a CSR for bulb03" do
      PledgeKeys.instance.product_id = "spec/files/product/00-D0-E5-03-00-03"

      # now create a CSR attribute with the specified name.
      client = Pledge.new
      csr = client.build_csr("rfc822name@example.com")
      expect(csr.subject.to_s).to include("00-D0-E5-03-00-03")

      File.open("tmp/csr_bulb03.csr", "wb") do |f| f.syswrite csr.to_der end
      expect(csr.verify(csr.public_key)).to be true
    end
  end

  describe "MASA public key" do
    it "should be a kind of public key" do
      b = PledgeKeys.instance.masa_cert
      expect(b).to be_kind_of(OpenSSL::X509::Certificate)
    end
  end

end
