require 'uri'
require 'openid_connect'

module Authentication
  module AuthnOidc
    module AuthenticateIdToken
      DecodeAndVerifyIdToken = CommandClass.new(
        dependencies: {
          provider_certificate: ::Authentication::AuthnOidc::AuthenticateIdToken::ProviderCertificate.new
        },
        inputs: %i(provider_uri id_token_jwt)
      ) do

        def call
          certs # may raise errors
          decoded_id_token # we decode the id token separately to propagate relevant errors
          verify_decoded_id_token
          decoded_attributes # return decoded attributes as hash
        end

        private

        def verify_decoded_id_token
          # Verify id_token expiration. OpenIDConnect requires to verify few claims.
          # Mask required claims such that effectively only expiration will be verified
          expected = { client_id: decoded_attributes[:aud] || decoded_attributes[:client_id],
                       issuer: decoded_attributes[:iss],
                       nonce: decoded_attributes[:nonce] }

          decoded_id_token.verify!(expected)
        rescue OpenIDConnect::ResponseObject::IdToken::ExpiredToken
          raise IdTokenExpired
        rescue => e
          raise IdTokenVerifyFailed, e.inspect
        end

        def certs
          @certs ||= @provider_certificate.fetch_certs(@provider_uri)
        end

        def decoded_attributes
          @decoded_attributes ||= decoded_id_token.raw_attributes
        end

        def decoded_id_token
          @decoded_id_token ||= OpenIDConnect::ResponseObject::IdToken.decode(
            @id_token_jwt,
            certs
          )
          Rails.logger.debug("[OIDC] Decode ID Token succeeded")
          @decoded_id_token
        rescue => e
          raise IdTokenInvalidFormat, e.inspect
        end
      end
    end
  end
end
