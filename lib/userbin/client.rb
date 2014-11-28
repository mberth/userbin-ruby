module Userbin
  class Client

    attr_accessor :request_context

    def self.install_proxy_methods(*names)
      names.each do |name|
        class_eval <<-RUBY, __FILE__, __LINE__ + 1
          def #{name}(*args)
            Userbin::User.new('$current').#{name}(*args)
          end
        RUBY
      end
    end

    install_proxy_methods :challenges, :events, :sessions, :pairings,
      :backup_codes, :generate_backup_codes, :trusted_devices,
      :enable_mfa!, :disable_mfa!

    def initialize(request, response, opts = {})
      # Save a reference in the per-request store so that the request
      # middleware in request.rb can access it
      RequestStore.store[:userbin] = self

      if response.class.name == 'ActionDispatch::Cookies::CookieJar'
        cookies = Userbin::CookieStore::Rack.new(response)
      else
        cookies = Userbin::CookieStore::Base.new(request, response)
      end

      @store = Userbin::TokenStore.new(cookies)

      @request_context = {
        ip: request.ip,
        user_agent: request.user_agent
      }
    end

    def session_token
      @store.session_token
    end

    def session_token=(session_token)
      @store.session_token = session_token
    end

    def authorize!
      unless logged_in?
        raise Userbin::UserUnauthorizedError,
          'Need to call login before authorize'
      end

      if session_token.expired?
        Userbin::Monitoring.heartbeat
      end

      if mfa_in_progress?
        logout
        raise Userbin::UserUnauthorizedError,
            'Logged out due to being unverified'
      end

      if mfa_required? && !device_trusted?
        raise Userbin::ChallengeRequiredError
      end
    end

    def logged_in?
      session_token.valid?
    end

    def login(user_id, user_attrs = {})
      @store.clear_session_token

      user = Userbin::User.new(user_id.to_s)
      session = user.sessions.create(
        user: user_attrs, trusted_device_token: @store.trusted_device_token)

      # Set the session token for use in all subsequent requests
      self.session_token = session.token

      session
    end

    def logout
      return unless logged_in?

      # Destroy the current session specified in the session token
      begin
        sessions.destroy('$current')
      rescue Userbin::ApiError # ignored
      end

      @store.clear_session_token
    end

    def trust_device(attrs = {})
      unless logged_in?
        raise Userbin::UserUnauthorizedError,
          'Need to call login before trusting device'
      end
      trusted_device = trusted_devices.create(attrs)

      # Set the session token for use in all subsequent requests
      @store.trusted_device_token = trusted_device.token
    end

    def mfa_enabled?
      session_token.mfa_enabled?
    end

    def device_trusted?
      session_token.device_trusted?
    end

    def mfa_in_progress?
      session_token.mfa_in_progress?
    end

    def mfa_required?
      session_token.mfa_required?
    end

    def has_default_pairing?
      session_token.has_default_pairing?
    end
  end
end
