# encoding: UTF-8
#
# a class for dealing with CSR Attributes as defined by RFC7030 section 4.5.2
#

# monkey patch some things.
class OpenSSL::ASN1::ASN1Data
  def is_sequence?
    false
  end
  def is_set?
    false
  end
end
class OpenSSL::ASN1::Sequence
  def is_sequence?
    true
  end
end
class OpenSSL::ASN1::Set
  def is_set?
    true
  end
end

class CSRAttributes
  attr_accessor :attributes
  attr_accessor :unstructured_attributes
  attr_accessor :rawentities

  def self.from_der(x)
    rawentities = OpenSSL::ASN1.decode(x)
    csr = new
    csr.rawentities = rawentities.value
    csr.process_attributes!
    csr
  end

  # https://tools.ietf.org/html/rfc5280#section-4.2.1.6 defines subjectAltName:
  # SubjectAltName ::= GeneralNames
  # GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
  # GeneralName ::= CHOICE {
  #        otherName                       [0]     OtherName,   <-- this one,
  #        rfc822Name                      [1]     IA5String,
  def self.rfc822NameChoice
    1
  end

  def self.otherNameChoice
    0
  end

  def self.acpNodeNameOID
    @acpoid ||= OpenSSL::ASN1::ObjectId.new("1.3.6.1.5.5.7.8.10")
  end

  def self.rfc822Name(x)
    # a is rfc822Name CHOICE from RFC7030, and the result is a sequence of SANs
    v = OpenSSL::ASN1::UTF8String.new(x, rfc822NameChoice, :EXPLICIT, :CONTEXT_SPECIFIC)
    return OpenSSL::ASN1::Sequence.new([v])
  end

  def self.otherName(x)
    # a is otherNameName CHOICE from RFC7030, and the result is a sequence of SANs
    v = OpenSSL::ASN1::IA5String.new(x, 0, :EXPLICIT, :CONTEXT_SPECIFIC)

    # this seq makes up the OtherName
    seq1 = OpenSSL::ASN1::Sequence.new([acpNodeNameOID,v], otherNameChoice, :EXPLICIT, :CONTEXT_SPECIFIC)
    # this is the SubjectAltName contents.
    return OpenSSL::ASN1::Sequence.new([seq1])
  end

  def initialize
    self.unstructured_attributes = Hash.new
    self.attributes = Hash.new
    self.rawentities = []
  end

  # return the sequence of subjectAltNames that have been requested
  # (usually just one item, but actually a sequence of CHOICE)
  def find_extReq
    attribute_by_oid("extReq")
  end

  # return the sequence of subjectAltNames that have been requested
  def find_subjectAltName
    extReq = find_extReq
    return [] unless extReq
    return [] unless extReq.is_a? OpenSSL::ASN1::Constructive # Set/Sequence

    #byebug
    san_list = []
    # this could get refactored when another thing needs to search for extensions
    extReq.value.each { |exten|
      if exten.is_a? OpenSSL::ASN1::Sequence
        if exten.value[0].is_a? OpenSSL::ASN1::ObjectId and
           exten.value[0].oid == subjectAltNameOid.oid

          # found it, return entire structure
          san_list << exten
        else
          exten.value.each { |exten2|
            if exten2.is_a? OpenSSL::ASN1::Constructive
              exten2.value.each { |exten3|
                if exten3.is_a? OpenSSL::ASN1::Constructive and
                  exten3.value[0].is_a? OpenSSL::ASN1::ObjectId and
                  exten3.value[0].oid == subjectAltNameOid.oid
                  san_list << exten3
                end
              }
            end
          }
        end
      end
    }
    return san_list
  end

  # this function looks through the subjectAltNames, and returns the one which
  # has an acpNodeNameOid.
  def find_rfc822NameOrOtherName
    os_san_list = find_subjectAltName

    return nil unless os_san_list.length > 0

    # loop through each each, looking for rfc822Name or otherNameChoice
    names = os_san_list.each { |sanitem|
      if sanitem.value.length >= 2 && sanitem.value[2].is_a?(OpenSSL::ASN1::OctetString)
        # third item is an OCTET street, which needs to be decoded.
        san = OpenSSL::ASN1.decode(sanitem.value[2].value)
        return nil unless (san and san.try(:value))

        san.value.each { |name|
          if name.is_a? OpenSSL::ASN1::ASN1Data
            name = name.value[0]
          end
          next unless (name.is_a? OpenSSL::ASN1::Constructive)
          next unless name.value.length >= 2
          if name.value[0].oid == CSRAttributes.acpNodeNameOID.oid
            return name.value[1].value[0].value
          end
        }
      end
    }

    return nil
  end

  def to_der
    # this implements the part:
    #      CsrAttrs ::= SEQUENCE SIZE (0..MAX) OF AttrOrOID

    list = []

    # canonical ordering by OID. Keys are always an OID number.
    keys = @unstructured_attributes.keys.sort
    keys.each{ |k|
      v  = @unstructured_attributes[k]
      n0 = v
      koid = OpenSSL::ASN1::ObjectId.new(k)
      if v.is_a? Array
        v0 = OpenSSL::ASN1::Set.new(v)
        n0 = OpenSSL::ASN1::Sequence.new([koid,v0])
      elsif v.is_a? OpenSSL::ASN1::Constructive
        n0 = OpenSSL::ASN1::Sequence.new([koid,v])
      end
      list << n0
    }
    @attributes.each { |k,v|
      koid = OpenSSL::ASN1::ObjectId.new(k)
      v0 = OpenSSL::ASN1::Set.new(
        [
          OpenSSL::ASN1::Sequence.new([v])
        ])
      list << OpenSSL::ASN1::Sequence.new([koid,v0])
    }

    n = OpenSSL::ASN1::Sequence.new(list)
    n.to_der
  end

  def add_oid(oidOrString)
    oid = oidOrString
    unless oidOrString.is_a? OpenSSL::ASN1::ObjectId
      oid = OpenSSL::ASN1::ObjectId.new(oidOrString)
    end

    # at this point, "oid" is definitely a object.
    k = oid.oid
    @unstructured_attributes[k] = oid
    oid
  end

  def make_attr_extension(extnID, critical, extnValue)
    critvalue = OpenSSL::ASN1::Boolean.new(critical)
    unless extnValue.is_a? String
      extnValue = extnValue.to_der
    end
    OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ObjectId.new(extnID),
                                 critvalue,
                                 OpenSSL::ASN1::OctetString.new(extnValue)])
  end

  # extReq/extensionRequest (1.2.840.113549.1.9.14).
  def add_ext_value(x, y)
    add_structured_attr(OpenSSL::ASN1::ObjectId.new("extReq"), make_attr_extension(x, true, y))
  end

  # other values which are not extension Requests, such as key type
  def add_simple_value(x, y)
    add_attr(OpenSSL::ASN1::ObjectId.new(x), y)
  end

  def add_otherNameSAN(san)
    add_ext_value("subjectAltName", CSRAttributes.otherName(san))
  end

  def find_attr_in_list(attributes, x)
    thing = nil
    return nil if attributes.nil?
    attributes.each { |attr|
      if attr.value[0].is_a? OpenSSL::ASN1::Sequence or
        attr.value[0].is_a? OpenSSL::ASN1::Set
        attr.value.each { |attr2|
          if attr2.is_a? OpenSSL::ASN1::Sequence and
            attr2.value[0].is_a? OpenSSL::ASN1::ObjectId and
            attr2.value[0].oid == x.oid
            thing = attr2
          end
        }
      else
        if attr.value[0].is_a? OpenSSL::ASN1::ObjectId and
          attr.value[0].oid == x.oid
          thing = attr.value[1]
        end
      end
    }
    return thing
  end

  def attribute_by_oid(oidthing)
    unless oidthing.is_a? OpenSSL::ASN1::ObjectId
      oidthing = OpenSSL::ASN1::ObjectId.new(oidthing)
    end
    @attributes[oidthing.oid] || @unstructured_attributes[oidthing.oid]
  end

  # this walks through the SEQ of attributes that is the CSR attributes, and for each
  # one, puts it into a hash based upon the OID.
  def process_attributes!
    @rawentities.each { |attr|
      case
      when (attr.is_a? OpenSSL::ASN1::ObjectId)
        oid = attr.oid
        @attributes[oid] = attr.value
      when (attr.is_a? OpenSSL::ASN1::Sequence)
        oid = attr.value[0].oid
        @attributes[oid] = attr.value[1]
      else
        # not sure what to do with something else.
        return false
      end
    }
    return true
  end

  def extReqOid
    @extReqOid ||= OpenSSL::ASN1::ObjectId.new("extReq")
  end

  def subjectAltNameOid
    @subjectAltNameOid ||= OpenSSL::ASN1::ObjectId.new("subjectAltName")
  end

  private

  # if the type is Set or Sequence, then extend the value.
  # if the item is nil, then use a Set by default
  def add_attr(x, y)
    if x.is_a? OpenSSL::ASN1::ObjectId
      x = x.oid
    end
    if @unstructured_attributes[x].nil?
      @unstructured_attributes[x] = OpenSSL::ASN1::Set.new([])
    end
    if @unstructured_attributes[x].is_a? OpenSSL::ASN1::Constructive
      @unstructured_attributes[x].value << y
    else
      # not constructive, so just replace value
      @unstructured_attributes[x] = y
    end
  end
  def add_structured_attr(x, y)
    if x.is_a? OpenSSL::ASN1::ObjectId
      x = x.oid
    end
    if @attributes[x].nil?
      @attributes[x] = OpenSSL::ASN1::Set.new([])
    end
    if @attributes[x].is_a? OpenSSL::ASN1::Constructive
      @attributes[x].value << y
    else
      # not constructive, so just replace value
      @attributes[x] = y
    end
  end

end
