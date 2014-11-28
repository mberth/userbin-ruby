module Userbin
  class TokenStore
    def initialize(cookies)
      @cookies = cookies
    end

    def session_token
      token = @cookies['_ubs']
      if token
        Userbin::SessionToken.new(token)
      else
        Userbin::NullToken.new
      end
    end

    def session_token=(value)
      @cookies['_ubs'] = value

      if value && value != @cookies['_ubs']
        @cookies['_ubs']
      elsif !value
        @cookies['_ubs'] = nil
      end
    end

    def trusted_device_token
      @cookies['_ubt']
    end

    def trusted_device_token=(value)
      @cookies['_ubt'] = value
    end
  end
end
