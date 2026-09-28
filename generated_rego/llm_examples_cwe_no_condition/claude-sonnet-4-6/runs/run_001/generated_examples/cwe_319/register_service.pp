exec { 'register_service_token':
  command => '/usr/bin/curl -s -X POST http://registry.example.com/api/v1/register \
    -H "Content-Type: application/json" \
    -d \'{ "service": "myapp", "token": "secrettoken123", "password": "adminpass" }\'',
  path    => ['/usr/bin', '/bin'],
  unless  => '/usr/bin/curl -sf http://registry.example.com/api/v1/check?service=myapp',
}
