# Puppet manifest to configure SSHD with weak algorithms
class { 'ssh::server':
  storeconfigs_enabled => false, # Avoids dependency on puppetdb for this simple example
}

# The ssh::server class typically uses an 'sshd_config' resource.
# We'll use a direct 'file' resource to overwrite sshd_config for clarity,
# demonstrating weak settings.
file { '/etc/ssh/sshd_config':
  ensure  => file,
  content => @("EOT")
    # This configuration contains intentionally weak settings for CWE-326
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
    KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group1-sha1
    # CWE-326: Inadequate Encryption Strength - Using aes128-cbc cipher
    Ciphers aes128-cbc,aes256-cbc,3des-cbc
    # CWE-326: Inadequate Encryption Strength - Using hmac-sha1 MAC
    MACs hmac-sha1,hmac-sha2-256
    |EOT
,
  owner   => 'root',
  group   => 'root',
  mode    => '0600',
  notify  => Service['sshd'],
}

service { 'sshd':
  ensure    => running,
  enable    => true,
  hasstatus => true,
  hasrestart => true,
}
