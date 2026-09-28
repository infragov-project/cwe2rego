aws_load_balancer { 'production-lb':
  ensure  => present,
  region  => 'us-east-1',
  listeners => [
    {
      protocol           => 'HTTP',
      load_balancer_port => 80,
      instance_protocol  => 'HTTP',
      instance_port      => 8080,
      ssl_certificate_id => undef,
    }
  ],
  ssl_policy   => undef,
  ssl_enabled  => false,
}

aws_load_balancer_listener { 'http-listener':
  load_balancer   => 'production-lb',
  protocol        => 'HTTP',
  port            => 80,
  target_protocol => 'HTTP',
  certificate_arn => undef,
  insecure        => true,
}
