http_request 'notify_deployment_webhook' do
  action :post
  url 'http://webhooks.example.com/deploy/notify'
  headers({ 'Content-Type' => 'application/json' })
  message({ 'environment' => node['env'], 'status' => 'deployed' }.to_json)
end
