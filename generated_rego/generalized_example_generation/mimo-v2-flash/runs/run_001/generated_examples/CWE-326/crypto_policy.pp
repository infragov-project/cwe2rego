file { '/etc/crypto/policy.conf':
  ensure  => file,
  content => "algorithm=3DES
key_length=112
hash=MD5",
}