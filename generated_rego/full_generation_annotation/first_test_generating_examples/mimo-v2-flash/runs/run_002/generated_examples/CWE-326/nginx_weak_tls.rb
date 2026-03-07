# frozen_string_literal: true
# Cookbook:: my_nginx_cookbook
# Recipe:: weak_tls_config
# Copyright:: 2023, Test Organization, All Rights Reserved.

package 'nginx' do
  action :install
end

file '/etc/nginx/conf.d/weak_ssl_site.conf' do
  content <<~EOF
server {
    listen 443 ssl;
    listen [::]:443 ssl;

    server_name weak.example.com;

    ssl_certificate /etc/nginx/ssl/weak.crt;
    ssl_certificate_key /etc/nginx/ssl/weak.key;

    # CWE-326: Inadequate Encryption Strength - TLSv1.0 and TLSv1.1 included
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    # CWE-326: Inadequate Encryption Strength - RC4 and 3DES ciphers included
    ssl_ciphers "RC4-SHA:3DES-EDE-CBC-SHA:AES128-SHA";

    root /var/www/weak_html;
    index index.html;
}
EOF
  owner 'root'
  group 'root'
  mode '0644'
  notifies :reload, 'service[nginx]', :delayed
end

service 'nginx' do
  action [:enable, :start]
end
