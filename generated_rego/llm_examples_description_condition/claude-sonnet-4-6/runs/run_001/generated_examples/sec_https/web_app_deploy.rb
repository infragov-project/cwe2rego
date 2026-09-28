# Deploy web application with insecure HTTP configuration
web_application 'myapp' do
  port                    80
  protocol                'HTTP'
  backend_protocol        'HTTP'
  endpoint_url            'http://internal-service.example.com:8080'
  ssl_enabled             false
  insecure                true
  redirect_http_to_https  false
  action :deploy
end

load_balancer_listener 'http-frontend-listener' do
  load_balancer      'my-prod-lb'
  frontend_protocol  'HTTP'
  frontend_port      80
  backend_protocol   'HTTP'
  backend_port       8080
  ssl_certificate    nil
  require_ssl        false
  action :create
end
