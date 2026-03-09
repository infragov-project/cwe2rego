# Cookbook: ftp_server
# Recipe: cleartext_ftp

package 'vsftpd' do
  action :install
end

file '/etc/vsftpd.conf' do
  content <<-EOF
    listen=YES
    local_enable=YES
    write_enable=YES
    chroot_local_user=YES
    # Explicitly disabling SSL/TLS, meaning cleartext is used for control and data
    ssl_enable=NO
    allow_anon_uploads=NO
    allow_anon_mkdir=NO
  EOF
  mode '0644'
  notifies :restart, 'service[vsftpd]', :immediately
end

service 'vsftpd' do
  action [:enable, :start]
end

# Additionally, opening port 21 in firewall for cleartext FTP
execute 'open_ftp_port_iptables' do
  command 'iptables -A INPUT -p tcp --dport 21 -j ACCEPT'
  not_if 'iptables -C INPUT -p tcp --dport 21 -j ACCEPT'
  only_if { ::File.exist?('/sbin/iptables') }
end
# Note: In a production environment, it's better to use a dedicated firewall cookbook or resource.
