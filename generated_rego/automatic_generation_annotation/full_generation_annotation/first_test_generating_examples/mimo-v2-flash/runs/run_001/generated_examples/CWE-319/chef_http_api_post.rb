# Cookbook:: service_registration
# Recipe:: default

http_request 'register_service_details' do
  url 'http://registration.insecure.net/register'
  payload ({ 'service_id' => 'abc-123', 'access_token' => 'plain-text-token' }).to_json
  headers({ 'Content-Type' => 'application/json' })
  action :post
end
