# frozen_string_literal: true
# Cookbook:: my_ssh_cookbook
# Recipe:: weak_kex_config
# Copyright:: 2023, Test Organization, All Rights Reserved.

package 'openssh-server' do
  action :install
end

# To clearly demonstrate the weakness, we'll overwrite a minimal sshd_config.
# In a real scenario, you'd use a template or append to existing config.
file '/etc/ssh/sshd_config' do
  content <<~EOF
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
SyslogFacility AUTHPRIV
LogLevel INFO
PermitRootLogin prohibit-password
ChallengeResponseAuthentication no
PasswordAuthentication yes
RSAAuthentication yes
PubkeyAuthentication yes
PermitEmptyPasswords no
Subsystem sftp /usr/lib/openssh/sftp-server
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
# CWE-326: Inadequate Encryption Strength - Using diffie-hellman-group1-sha1 key exchange
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp256,diffie-hellman-group1-sha1
# CWE-326: Inadequate Encryption Strength - Using 3des-cbc cipher
Ciphers aes128-cbc,aes256-cbc,3des-cbc
# CWE-326: Inadequate Encryption Strength - Using hmac-sha1 MAC
MACs hmac-sha1,hmac-sha2-256
EOF
  owner 'root'
  group 'root'
  mode '0600'
  notifies :restart, 'service[ssh]', :delayed
end

service 'ssh' do
  service_name 'sshd' # On some systems, the service is called 'sshd'
  action [:enable, :start]
end
