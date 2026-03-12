exec { 'download_insecure_archive':
  command  => 'wget http://insecure.internal.example.com/downloads/archive.tar.gz -O /tmp/archive.tar.gz', # CWE-319: Uses HTTP protocol for download
  path     => ['/usr/bin', '/bin'],
  creates  => '/tmp/archive.tar.gz',
  user     => 'root',
  group    => 'root',
}