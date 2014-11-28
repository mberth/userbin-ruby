require 'jwt'

module Userbin
  class SessionToken
    def initialize(token)
      if token
        @jwt = Userbin::JWT.new(token)
      end
    end

    def to_s
      @jwt.to_token
    end

    def expired?
      @jwt.expired?
    end

    def device_trusted?
      @jwt.payload['tru'] == 1
    end

    def has_default_pairing?
      @jwt.payload['dpr'] > 0
    end

    def mfa_enabled?
      @jwt.payload['mfa'] == 1
    end

    def mfa_in_progress?
      @jwt.payload['chg'] == 1
    end

    def mfa_required?
      @jwt.payload['vfy'] > 0
    end

    # This is a real SessionToken, always return true.
    def valid?
      true
    end
  end

  # A Null Object that serves as a placeholder for a token. Used when there is
  # no real token yet (or anymore).
  class NullToken

    def to_s
      "null token"
    end

    def expired?
      # we don't want to refresh a NullToken
      false
    end

    def device_trusted?
      false
    end

    def has_default_pairing?
      false
    end

    def mfa_enabled?
      false
    end

    def mfa_in_progress?
      false
    end

    def mfa_required?
      false
    end

    # This is not a real SessionToken, always return false
    def valid?
      false
    end
  end
end
