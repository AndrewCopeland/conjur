#!/usr/bin/env ruby

require 'conjur-api'
require 'conjur-cli'
require 'restclient'

Conjur.configuration.apply_cert_config!
Conjur.log = $stderr

filename = "/run/conjur/access-token"
username = ENV['CONJUR_AUTHN_LOGIN'] or raise "No CONJUR_AUTHN_LOGIN found in the environment"

$stderr.puts "Authenticating at #{Conjur.configuration.authn_url}"
$stderr.puts "Authenticating with username #{username.inspect}"

authenticate = lambda {
  Conjur::API.authenticate username, ""
}

while true
  begin
    authenticate.call
    break
  rescue
    $stderr.puts $!
    sleep 5
  end
end

$stderr.puts "Initial authentication successful"

Conjur::Authenticator.run authenticate: authenticate, filename: filename
