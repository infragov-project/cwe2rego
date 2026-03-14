yumrepo { 'internal_packages':
  baseurl  => 'http://repo.internal.com/rpm',
  enabled  => 1,
  gpgcheck => 0,
  descr    => 'Insecure Internal Repository',
}