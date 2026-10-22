# A Ruby call site for spike S2's C9: one RSA key generated, one not.
require "openssl"

class Signer
  def initialize
    @key = OpenSSL::PKey::RSA.new(2048)
  end

  def digest(data)
    OpenSSL::Digest::SHA256.hexdigest(data)
  end
end

# OpenSSL::PKey::RSA.new(1024) in a comment is not a call
