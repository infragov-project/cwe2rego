# In a Chef recipe

apache_module 'ssl' do
  enable true
end

file '/etc/apache2/mods-available/ssl.conf' do
  content <<-EOF
    <IfModule mod_ssl.c>
    SSLProtocol all -SSLv2 -SSLv3 -TLSv1.2 -TLSv1.3 # TLSv1.0/1.1 disabled, but ciphers are weak
    # CWE-326: Weak or Insecure Cipher Suites - explicitly including RC4 and DES
    SSLCipherSuite "HIGH:!aNULL:!MD5:RC4-SHA:DES-CBC3-SHA:AES128-SHA"
    SSLHonorCipherOrder on
    SSLCertificateFile /etc/ssl/certs/ssl-cert-snakeoil.pem
    SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key
    </IfModule>
  EOF
  owner 'root'
  group 'root'
  mode '0644'
  notifies :reload, 'service[apache2]', :delayed
end

service 'apache2' do
  action :nothing # Defined to allow notification
end