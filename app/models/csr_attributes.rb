#
# a class for dealing with CSR Attributes as defined by RFC7030 section 4.5.2
#
class CSRAttributes
  attr_accessor :attributes

  def self.from_der(x)
    @attributes = OpenSSL::ASN1.decode(x)
    ca = new
    ca.attributes = @attributes.value
    ca
  end

  # https://tools.ietf.org/html/rfc5280#section-4.2.1.6 defines subjectAltName:
  # SubjectAltName ::= GeneralNames
  # GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
  # GeneralName ::= CHOICE {
  #        otherName                       [0]     OtherName,
  #        rfc822Name                      [1]     IA5String,   <-- this one
  def self.rfc822NameChoice
    1
  end

  def self.rfc822Name(x)
    # a is rfc822Name CHOICE from RFC7030, and the result is a sequence of SANs
    v = OpenSSL::ASN1::UTF8String.new(x, rfc822NameChoice, :EXPLICIT, :CONTEXT_SPECIFIC)
    return OpenSSL::ASN1::Sequence.new([v])
  end

  def initialize
    self.attributes = []
  end

  def to_der
    n = OpenSSL::ASN1::Sequence.new(@attributes)
    n.to_der
  end

  # return the sequence of subjectAltNames that have been requested
  # (usually just one item, but actually a sequence of CHOICE)
  def find_subjectAltName
    find_attr(OpenSSL::ASN1::ObjectId.new("subjectAltName"))
  end

  def add_oid(x)
    @attributes << OpenSSL::ASN1::ObjectId.new(x)
  end

  def make_attr_pair(x,y)
    OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ObjectId.new(x),
                                 OpenSSL::ASN1::Set.new([y])])
  end

  def add_attr(x, y)
    @attributes << make_attr_pair(x,y)
  end

  def find_attr(x)
    things = @attributes.select { |attr|
      attr.is_a? OpenSSL::ASN1::Sequence and
        attr.value[0].is_a? OpenSSL::ASN1::ObjectId and
        attr.value[0].oid == x.oid
    }
    if things.first
      t = things.first
      s = t.value[1]
      return s.value
    end
    return []
  end

end
