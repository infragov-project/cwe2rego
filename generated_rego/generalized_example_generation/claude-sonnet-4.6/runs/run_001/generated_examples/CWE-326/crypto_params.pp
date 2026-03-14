class { 'system::crypto':
  dh_param_size        => 768,
  elliptic_curve       => 'P-192',
  signature_algorithm  => 'sha1WithRSAEncryption',
  allow_insecure       => true,
}