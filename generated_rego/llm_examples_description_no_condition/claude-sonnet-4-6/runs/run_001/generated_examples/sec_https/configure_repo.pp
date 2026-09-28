yumrepo { 'internal-stable':
  ensure   => present,
  baseurl  => 'http://repo.example.com/stable/el7/x86_64/',
  descr    => 'Internal Stable Repository',
  enabled  => 1,
  gpgcheck => 0,
}
