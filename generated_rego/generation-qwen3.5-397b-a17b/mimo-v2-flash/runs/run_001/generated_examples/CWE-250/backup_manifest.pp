exec { 'run_backup_job':
  command => '/usr/local/bin/backup.sh',
  user    => 'root',
  path    => ['/usr/bin', '/bin'],
  timeout => 0,
}