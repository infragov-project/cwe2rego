aws_load_balancer_listener 'http_frontend_listener' do
  load_balancer_arn 'arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/prod-lb/abc123'
  port 80
  protocol 'HTTP'
  default_action(
    type: 'forward',
    target_group_arn: 'arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/prod-tg/def456'
  )
  action :create
end

aws_load_balancer_target_group 'prod_target_group' do
  name 'prod-tg'
  port 80
  protocol 'HTTP'
  vpc_id 'vpc-0abc12345'
  health_check_protocol 'HTTP'
  health_check_path '/health'
  action :create
end
