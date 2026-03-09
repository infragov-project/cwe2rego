# -*- coding: utf-8 -*-
#
# Configures a database with encryption explicitly disabled.

file '/tmp/mycustomdb_config.yml' do
  content <<-EOF
    database:
      host: localhost
      port: 5432
      username: dbuser
      password: dbpassword
      encryption_enabled: false # CWE-326: Inadequate Encryption Strength - Disabled Encryption at Rest
      encryption_algorithm: none
  EOF
  owner 'root'
  group 'root'
  mode '0600'
end
