bash 'disable_ssl' do
  code <<-EOF
    echo "ssl_enabled=false" >> /etc/app/config
    echo "protocol=http" >> /etc/app/config
  EOF
end