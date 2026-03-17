user { 'legacyuser':
  ensure   => present,
  password => '$1$salt$MD5HASHExample1', # Weak Cryptographic Algorithm (MD5 for password hash)
  comment  => 'User with MD5 hashed password',
}
