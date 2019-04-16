require 'singleton'
require 'byebug'
require 'chariwt'
require 'json'

class Smarkaklink < Pledge

  # this initializes the system with a self-signed IDevID.
  def generate_selfidevid(dir = "db/smarkaklink")
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

  def enroll_with_smarkaklink_manufacturer(dpp)
    self.jrc_uri = dpp.smarkaklink_enroll_url

    request = Net::HTTP::Post.new(jrc_uri)
    request.body = idevid_enroll_json
    request.content_type = 'application/json'
    request['Accept'] = 'application/pkcs7'
    response = http_handler.request request

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

  def voucher_request_json(dpp)
    # TODO: Add padding
    ec = OpenSSL::PKey::EC::IES.new(dpp.ecdsa_key, "algorithm")
    encrypted_nonce = ec.public_encrypt(self.sp_nonce)
    { "voucher-request challenge": { "voucher-challenge-nonce": Base64.urlsafe_encode64(encrypted_nonce) } }.to_json
  end

  def process_voucher_request_content_type(type, body)
    ct = Mail::Parsers::ContentTypeParser.parse(type)

    begin
      case [ct.main_type, ct.sub_type]
      when ['application', 'json']
        voucher_request = Chariwt::Voucher.from_pkcs7(body.b, http_handler.peer_cert)
        if voucher_request.nonce != self.sp_nonce
          puts "Invalid voucher-challenge-nonce from AR #{http_handler.address}"
        else
          puts "Connection with AR validated"
        end
      else
        raise ArgumentError
      end
    end
  end

  def fetch_voucher_request_url(dpp)
    URI.join("https://" + dpp.llv6, "/.well-known/est/requestvoucherrequest")
  end

  def fetch_voucher_request(dpp)
    self.jrc_uri = request_voucher_request_url(dpp)

    request = Net::HTTP::Post.new(self.jrc_uri)
    request.body = voucher_request_json(dpp)
    request.content_type = 'application/json'
    request['Accept'] = 'application/voucher-cms+json'
    response = http_handler.request request

    case response
    when Net::HTTPBadRequest, Net::HTTPNotFound
      puts "AR #{jrc_uri} refuses smarkaklink voucher request request: #{response.to_s} #{response.code}"

    when Net::HTTPSuccess
      ct = response['Content-Type']
      voucher = process_voucher_request_content_type(ct, response.body)
    else
      raise ArgumentError
    end

    return voucher
  end

  def process_voucher_url(dpp)
    URI.join("https://" + dpp.llv6, "/.well-known/est/voucher")
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
    URI.join("https://" + dpp.llv6, "/.well-known/est/cacerts")
  end

  def request_ca_list(dpp)
    request = Net::HTTP::Get.new(self.jrc_ui)
    request['Accept'] = 'application/pkcs7-mime'
    response = http_handler.request request

    case response
    when Net::HTTPBadRequest, Net::HTTPNotFound
      puts "AR #{self.jrc_ui} refuses to list CA certificates: #{response.to_s} #{response.code}"

    when Net::HTTPSuccess
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
    URI.join("https://" + dpp.llv6, "/.well-known/est/simpleenroll")
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
    URI.join("https://" + dpp.llv6, "/.well-known/est/enrollstatus")
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

  def smarkaklink_enroll(dpp)
    # Enroll with the manufacturer
    enroll_with_smarkaklink_manufacturer(dpp)

    # Connect to BRSKI join network
    puts "Connect to #{dpp.essid}"
    puts "Ensure that IPv6 LL #{dpp.llv6} is alive"

    # Connect to Adolescent Registrar (AR)
    # Create TLS connection to port 8443

    # Pledge Requests Voucher-Request from the Adolescent Registrar
    voucher = fetch_voucher_request(dpp)

    # Smart-Phone connects to MASA
    puts "Connect to Internet-available network"
    # TODO: Retrieve MASA-URL
    signed_voucher = get_voucher(nil, voucher)

    # Smartpledge processing of voucher
    puts "Connect to #{dpp.essid}"
    puts "Ensure that IPv6 LL #{dpp.llv6} is alive"
    process_voucher(dpp, signed_voucher)

    # Smartphone enrolls
    csr = request_ca_list(dpp)

    perform_simple_enroll(dpp, csr)
    validate_enroll(dpp)
  end

end
