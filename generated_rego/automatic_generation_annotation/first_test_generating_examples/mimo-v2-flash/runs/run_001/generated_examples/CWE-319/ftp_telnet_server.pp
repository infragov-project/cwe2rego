# ftp_telnet_server.pp

package { 'vsftpd':
  ensure => installed,
}

file { '/etc/vsftpd.conf':
  ensure  => file,
  owner   => 'root',
  group   => 'root',
  mode    => '0644',
  content => @("VSFTPD_CONF")
    listen=YES
    listen_ipv6=NO
    anonymous_enable=NO
    local_enable=YES
    write_enable=YES
    local_umask=022
    dirmessage_enable=YES
    use_localtime=YES
    xferlog_enable=YES
    connect_from_port_20=YES
    xferlog_file=/var/log/vsftpd.log
    ftpd_banner=Welcome to MyApp FTP service.
    secure_chroot_dir=/var/run/vsftpd/empty
    pam_service_name=vsftpd
    rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
    rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
    ssl_enable=NO # CWE-319 - Explicitly disabling SSL
    pasv_enable=YES
    pasv_min_port=40000
    pasv_max_port=50000
    port_enable=YES # CWE-319 - Port 21 default is FTP
    VSFTPD_CONF
  require => Package['vsftpd'],
  notify  => Service['vsftpd'],
}

service { 'vsftpd':
  ensure    => running,
  enable    => true,
  subscribe => File['/etc/vsftpd.conf'],
}

# Enable Telnet server - CWE-319
package { 'telnetd':
  ensure => installed,
}

file { '/etc/xinetd.d/telnet':
  ensure  => file,
  owner   => 'root',
  group   => 'root',
  mode    => '0644',
  content => @("TELNET_CONF")
    service telnet
    {
        disable = no # CWE-319
        flags           = REUSE
        socket_type     = stream
        wait            = no
        user            = root
        server          = /usr/sbin/in.telnetd
        log_on_failure  += USERID
    }
    TELNET_CONF
  require => Package['telnetd'],
  notify  => Service['xinetd'],
}

service { 'xinetd':
  ensure    => running,
  enable    => true,
  subscribe => File['/etc/xinetd.d/telnet'],
}
