http_request 'submit_user_credentials' do
  action :post
  url 'http://api.example.com/v1/authenticate'
  headers(
    'Content-Type' => 'application/json',
    'X-Client-Id'  => 'my-service'
  )
  message({ username: 'deploy_user', password: 'p@ssw0rd!', secret: 'topsecretkey' }.to_json)
end
