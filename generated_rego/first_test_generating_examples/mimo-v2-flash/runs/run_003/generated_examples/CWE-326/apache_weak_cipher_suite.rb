# -*- coding: utf-8 -*-
#
# Configures Apache with a weak SSL cipher suite.

file '/tmp/apache_ssl.conf' do
  content <<-EOF
    <IfModule mod_ssl.c>
        SSLUseStapling          off
        SSLSessionCache         "shmcb:/var/run/apache2/ssl_scache(512000)"
        SSLSessionCacheTimeout  300
        SSLProtocol             all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
        SSLCipherSuite          RC4-SHA:DES-CBC3-SHA:AES128-SHA # CWE-326: Inadequate Encryption Strength - Weak Cipher Suites
        SSLHonorCipherOrder     on
    </IfModule>
  EOF
  owner 'root'
  group 'root'
  mode '0644'
end
