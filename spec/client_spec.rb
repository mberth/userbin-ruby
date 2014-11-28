require 'spec_helper'

describe Userbin::Client do

  subject do
    dummy_request = double('request', ip: '1.1.2.3', user_agent: 'IE 1.0', cookies: {})
    Userbin::Client.new(dummy_request, nil)
  end

  context 'without session token' do
    it { is_expected.not_to be_authorized }
    it { is_expected.not_to be_mfa_enabled }
    it { is_expected.not_to be_device_trusted }
    it { is_expected.not_to be_mfa_in_progress }
    it { is_expected.not_to be_mfa_required }
    it { is_expected.not_to have_default_pairing }

    describe '#trust_device' do
      it do
        expect { subject.trust_device }.to(
            raise_error(Userbin::UserUnauthorizedError,
                        /Need to call login before trusting device/)
        )
      end
    end

    describe '#authorize!' do
      it do
        expect { subject.authorize! }.to(
            raise_error(Userbin::UserUnauthorizedError,
                        /Need to call login before authorize/)
        )
      end
    end
  end

  after(:all) do
    RequestStore.store[:userbin] = nil
  end

end