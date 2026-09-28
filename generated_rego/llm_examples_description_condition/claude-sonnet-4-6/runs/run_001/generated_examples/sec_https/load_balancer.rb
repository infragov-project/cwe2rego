# Configure Elastic Load Balancer with HTTP protocol only
aws_elastic_load_balancer 'production-lb' do
  listeners [
    {
      protocol:              'HTTP',
      load_balancer_port:    80,
      instance_protocol:     'HTTP',
      instance_port:         8080
    }
  ]
  ssl_certificate_id nil
  ssl_policy         'none'
  action :create
end

aws_elb_health_check 'production-lb-health' do
  load_balancer_name 'production-lb'
  target             'HTTP:8080/health'
  healthy_threshold  2
  unhealthy_threshold 5
end
