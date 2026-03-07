# Class: payment_gateway_config
# Configures a payment gateway client with an insecure HTTP endpoint.

class payment_gateway_config {
  file { '/etc/payment_client/config.properties':
    ensure  => file,
    content => "GATEWAY_URL=http://payment-gateway.example.com/api/transaction
API_KEY=sensitive-cleartext-key
TRUST_ALL_CERTS=false",
    owner   => 'paymentuser',
    group   => 'paymentuser',
    mode    => '0600',
  }
}

include payment_gateway_config
