require 'singleton'
require 'byebug'
require 'chariwt'
require 'json'

class Smarkaklink < Pledge

  MASAURLExtn_OID = "1.3.6.1.4.1.46930.2".freeze

  def smarkaklink_pledge_handler
    options = {
      :verify_mode => OpenSSL::SSL::VERIFY_NONE,
      :use_ssl => true,
      :cert    => PledgeKeys.instance.ldevid_pubkey,
      :key     => PledgeKeys.instance.ldevid_privkey
    }
    @kaklink_pledge_handler ||= Net::HTTP.start(jrc_uri.host, jrc_uri.port, options)
  end

  # this initializes the system with a self-signed IDevID.
  def self.generate_selfidevid(dir = "db/smarkaklink")
    pi = PledgeKeys.instance
    pi.product_id = dir if dir

    curve = pi.curve

    if File.exists?(pi.priv_file)
      puts "SelfID using existing key at: #{pi.priv_file}" unless Rails.env.test?
      self_key = OpenSSL::PKey.read(File.open(pi.priv_file))
    else
      # the CA's public/private key - 3*1024 + 8
      self_key = OpenSSL::PKey::EC.new(curve)
      self_key.generate_key
      File.open(pi.priv_file, "w", 0600) do |f| f.write self_key.to_pem end
      puts "SelfID wrote private key to #{pi.priv_file}" unless Rails.env.test?
    end

    self_crt  = OpenSSL::X509::Certificate.new
    # cf. RFC 5280 - to make it a "v3" certificate
    self_crt.version = 2
    serialno=SystemVariable.randomseq(:serialnumber)
    self_crt.serial  = serialno
    dn = sprintf("/C=Canada/OU=Smarkaklink-%d", serialno)
    self_crt.subject = OpenSSL::X509::Name.parse dn

    # this is self-signed certificate
    self_crt.issuer = self_crt.subject
    self_crt.public_key = self_key
    self_crt.not_before = Time.now

    # 2 years validity
    self_crt.not_after = self_crt.not_before + 2 * 365 * 24 * 60 * 60

    # Extension Factory -- no extensions needed
    self_crt.sign(self_key, OpenSSL::Digest::SHA256.new)

    File.open(pi.pub_file, 'w') do |f|
      f.write self_crt.to_pem
    end
    puts "SelfId certificate written to: #{pi.pub_file}" unless Rails.env.test?

  end

  def security_options
    { :verify_mode => OpenSSL::SSL::VERIFY_NONE,
      :use_ssl => jrc_uri.scheme == 'https',
      # use a dummy CA if testing, and might be connecting to testing highway.
      :ca_file => (Rails.env.test? ? PledgeKeys.instance.testing_capath : nil),
      :cert    => PledgeKeys.instance.idevid_pubkey,
      :key     => PledgeKeys.instance.idevid_privkey
    }
  end

  def idevid_enroll_json
    { cert: Base64.urlsafe_encode64(PledgeKeys.instance.idevid_pubkey.to_der) }.to_json
  end

  def process_enroll_content_type(type, body)
    ct = Mail::Parsers::ContentTypeParser.parse(type)

    begin
      case [ct.main_type, ct.sub_type]
      when ['application', 'pkcs7']
        File.open(PledgeKeys.instance.lpub_file, "wb") do |f|
          f.syswrite body.b
        end
      else
        raise ArgumentError
      end
    end
  end

  def enroll_with_smarkaklink_manufacturer(dpp, saveto = nil)
    self.jrc_uri = dpp.smarkaklink_enroll_url

    request = Net::HTTP::Post.new(jrc_uri)
    request.body = idevid_enroll_json
    request.content_type = 'application/json'
    request['Accept'] = 'application/pkcs7'
    response = http_handler.request request
    if saveto
      File.open("tmp/enroll_#{PledgeKeys.instance.hunt_for_serial_number}.pkcs7", "wb") do |f|
        f.puts response.body
      end
    end

    case response
    when Net::HTTPBadRequest, Net::HTTPNotFound
      puts "MASA #{jrc_uri} refuses smarkaklink enroll: #{response.to_s} #{response.code}"

    when Net::HTTPSuccess
      ct = response['Content-Type']
      process_enroll_content_type(ct, response.body)
    else
      raise ArgumentError
    end

    return PledgeKeys.instance.ldevid_pubkey
  end

  def voucher_request_json(dpp, nonce)
    # TODO: Add padding
    ec = OpenSSL::PKey::EC::IES.new(dpp.key, "algorithm")
    encrypted_nonce = ec.public_encrypt(nonce)
    { "ietf:request-voucher-request":
        { "voucher-challenge-nonce": Base64.urlsafe_encode64(encrypted_nonce) }
    }.to_json
  end

  def process_voucher_request_content_type(type, body, nonce, saveto = nil)
    ct = Mail::Parsers::ContentTypeParser.parse(type)

    begin
      case [ct.main_type, ct.sub_type]
      when ['application', 'voucher-cms+json']

        if saveto
          File.open("tmp/vr_#{PledgeKeys.instance.hunt_for_serial_number}.pkcs7", "wb") do |f|
            f.write body.b
          end
        end
        voucher_request = Chariwt::VoucherRequest.from_pkcs7(body.b)

        if voucher_request.attributes["voucher-challenge-nonce"] != nonce
          puts "Invalid voucher-challenge-nonce from AR #{smarkaklink_pledge_handler.address}"
        else
          puts "Connection with AR validated"
          voucher_request
        end
      else
        puts "Invalid content-type #{type}"
        raise ArgumentError
      end
    end
  end

  def fetch_voucher_request_url(dpp)
    URI.join("https://#{dpp.ulanodename_iauthority}:8443", "/.well-known/est/requestvoucherrequest")
  end

  def fetch_voucher_request(dpp, saveto = nil)
    self.jrc_uri = fetch_voucher_request_url(dpp)

    sp_nonce = SecureRandom.base64(16)

    request = Net::HTTP::Post.new(self.jrc_uri)
    request.body = voucher_request_json(dpp, sp_nonce)
    request.content_type = 'application/json'
    request['Accept'] = 'application/voucher-cms+json'
    response = smarkaklink_pledge_handler.request request

    if saveto
      File.open("tmp/spnonce_#{PledgeKeys.instance.hunt_for_serial_number}", "w") do |f|
        f.write sp_nonce
      end
      File.open("tmp/rvr_#{PledgeKeys.instance.hunt_for_serial_number}.json", "w") do |f|
        f.write request.body
      end
    end

    # Retrieve and store the MASA URL provided in the AR's certificate
    @masa_url = smarkaklink_pledge_handler.peer_cert().extensions.select { |ext| ext.oid == MASAURLExtn_OID }.first.value()[2..-1]

    case response
    when Net::HTTPBadRequest, Net::HTTPNotFound
      puts "AR #{jrc_uri} refuses smarkaklink voucher request request: #{response.to_s} #{response.code}"

    when Net::HTTPSuccess
      ct = response['Content-Type']
      voucher = response.body
      process_voucher_request_content_type(ct, voucher, sp_nonce, saveto)
    else
      raise ArgumentError
    end

    return voucher
  end

  def process_voucher_url(dpp)
    URI.join("https://[#{dpp.llv6}]", "/.well-known/est/voucher")
  end

  def process_voucher(dpp, voucher)
    self.jrc_uri = process_voucher_url(dpp)
    request = Net::HTTP::Post.new(self.jrc_uri)
    request.body = voucher.json_voucher
    request.content_type = 'application/json'
    response = http_handler.request request

    case response
    when Net::HTTPBadRequest, Net::HTTPNotFound
      puts "AR #{self.jrc_uri} refuses MASA's voucher: #{response.to_s} #{response.code}"

    when Net::HTTPSuccess
      puts "AR #{self.jrc_ui} validates MASA's voucher"
    else
      raise ArgumentError
    end
  end

  def generate_csr
    csr = OpenSSL::X509::Request.new
    csr.public_key = PledgeKeys.instance.idevid_pubkey
  end

  def request_ca_list_url(dpp)
    URI.join("https://[#{dpp.llv6}]", "/.well-known/est/cacerts")
  end

  def request_ca_list(dpp, saveto = nil)
    request = Net::HTTP::Get.new(self.jrc_ui)
    request['Accept'] = 'application/pkcs7-mime'
    response = http_handler.request request

    case response
    when Net::HTTPBadRequest, Net::HTTPNotFound
      puts "AR #{self.jrc_ui} refuses to list CA certificates: #{response.to_s} #{response.code}"

    when Net::HTTPSuccess
      if saveto
        File.open("tmp/cas.pkcs", "w") do |f|
          f.puts response.body
        end
      end

      data = OpenSSL::CMS::ContentInfo.new(response.body.b)
      # Extract CA Certificates
      cert_store = OpenSSL::X509::Store.new

      # walk through the certificate list and look for any self-signed certificates
      # and put them into the cert_store.
      certs = data.certificates
      certs.select{ |cert| cert.issuer == cert.subject }.each { |cert| cert_store.add_cert(cert) }

      # Update the security options
      security_options[:ca_file] = ca_store

      generate_csr

    else
      raise ArgumentError
    end
  end

  def perform_simple_enroll_url(dpp)
    URI.join("https://[#{dpp.llv6}]", "/.well-known/est/simpleenroll")
  end

  def perform_simple_enroll(dpp, csr)
    self.jrc_uri = perform_simple_enroll_url(dpp)
    request = Net::HTTP::Post.new(self.jrc_uri)
    request.body = csr.to_der
    # Send PKCS10
    # Receive pkcs7-mime
    request.content_type = 'application/pkcs10'
    request['Accept'] = 'application/pkcs7-mime'
    response = http_handler.request request

    if saveto
      File.open("tmp/#{PledgeKeys.instance.hunt_for_serial_number}.csr", "w") do |f|
        f.puts csr.to_pemy
      end
    end

    case response
    when Net::HTTPBadRequest, Net::HTTPNotFound
      puts "AR #{self.jrc_ui} refuses MASA's voucher: #{response.to_s} #{response.code}"

    when Net::HTTPSuccess
      puts "AR #{self.jrc_ui} signed CSR"
      # TODO: keep connection open - Connection 1
      cert = OpenSSL::X509::Certificate.new(response.body)
      validate_status(cert)
      # Update security options
      security_options[:verify_mode] = OpenSSL::SSL::VERIFY_PEER
      security_options[:cert] = cert
      cert
    else
      raise ArgumentError
    end
  end

  def validate_enroll_json
    {
      "version": "1",
      "Status": "TRUE",
      "Reason": "Enroll completed",
      "reason-context": "Smarkaklink process finished"
    }.to_json
  end

  def validate_enroll_url(dpp)
    URI.join("https://[#{dpp.llv6}]", "/.well-known/est/enrollstatus")
  end

  def validate_enroll(dpp)
    self.jrc_uri = validate_enroll_url(dpp)
    request = Net::HTTP::Post.new(self.jrc_uri)
    request.body = validate_enroll_json
    request.content_type = 'application/json'
    response = http_handler.request request

    case response
    when Net::HTTPBadRequest, Net::HTTPNotFound
      puts "AR #{jrc_uri} refuses smarkaklink enroll validation: #{response.to_s} #{response.code}"

    when Net::HTTPSuccess
      # TODO: Close connection 1
    else
      raise ArgumentError
    end
  end

  def extract_serial_number(vr)
    cert = smarkaklink_pledge_handler.peer_cert
    vr.serialNumber = hunt_for_serial_number_from_cert(cert)
  end

  def masa_pubkey
    nil
  end

  def get_voucher(saveto, voucher)
    # TODO: handle complete URI given in extension
    self.jrc_uri = URI.join("https://" + @masa_url, "/.well-known/est/requestvoucher")
    super(saveto, voucher)
  end

  def smarkaklink_enroll(dpp, saveto = nil)
    # Enroll with the manufacturer
    enroll_with_smarkaklink_manufacturer(dpp, saveto)

    # Connect to BRSKI join network
    puts "Connect to #{dpp.essid}"
    puts "Ensure that URL #{fetch_voucher_request_url(dpp)} is alive"

    # Connect to Adolescent Registrar (AR)
    # Create TLS connection to port 8443

    # Pledge Requests Voucher-Request from the Adolescent Registrar
    voucher = fetch_voucher_request(dpp, saveto)

    # Smart-Phone connects to MASA
    puts "Connect to Internet-available network"
    signed_voucher = get_voucher(saveto, voucher)

    unless signed_voucher
      puts "Failed!"
      return
    end

    # Smartpledge processing of voucher
    puts "Connect to #{dpp.essid}"
    puts "Ensure that URL #{fetch_voucher_request_url(dpp)} is alive"
    process_voucher(dpp, signed_voucher)

    # Smartphone enrolls
    csr = request_ca_list(dpp, saveto)

    perform_simple_enroll(dpp, csr)
    validate_enroll(dpp)
  end

end
