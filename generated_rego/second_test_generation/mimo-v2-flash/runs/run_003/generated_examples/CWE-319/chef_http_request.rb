http_request 'send_health_check_over_http' do
  url 'http://monitoring.internal/healthcheck'
  message '{"hostname": "{{node.hostname}}", "status": "OK", "app_version": "1.0", "private_key": "ssh-rsa AAAA..."}'
  action :post
  headers({
    'Content-Type' => 'application/json'
  })
end
