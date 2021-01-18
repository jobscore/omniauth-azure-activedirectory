#-------------------------------------------------------------------------------
# Copyright (c) 2015 Micorosft Corporation
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#-------------------------------------------------------------------------------

require 'jwt'
require 'omniauth'
require 'openssl'
require 'securerandom'

module OmniAuth
  module Strategies
    # A strategy for authentication against Azure Active Directory.
    class AzureActiveDirectoryMultitenant < AzureActiveDirectory
      def raw_authorize_endpoint_url
      'https://login.microsoftonline.com/common/oauth2/authorize'
      end

      def authorize_endpoint_url
        uri = URI(raw_authorize_endpoint_url)
        uri.query = URI.encode_www_form(client_id: client_id,
                                        redirect_uri: 'LucasIsTesting',
                                        response_mode: response_mode,
                                        response_type: response_type,
                                        nonce: new_nonce)
        uri.to_s
      end

      def verify_options
        { verify_expiration: true,
          verify_not_before: true,
          verify_iat: true,
          verify_aud: true,
          'aud' => client_id }
      end

      def callback_url
        full_host + callback_path
      end
    end
  end
end

OmniAuth.config.add_camelization 'azure_activedirectory_multitenant', 'AzureActiveDirectoryMultitenant'
