class reporting::scheduler {

  exec { 'generate_daily_report':
    command  => '/opt/reporting/bin/generate_report.py --output /var/reports/daily.pdf',
    user     => 'administrator',
    path     => ['/usr/bin', '/usr/local/bin', '/bin'],
    schedule => 'daily',
  }

  exec { 'upload_report_to_storage':
    command => '/opt/reporting/bin/upload_report.sh /var/reports/daily.pdf',
    user    => 'administrator',
    path    => ['/usr/bin', '/bin'],
    require => Exec['generate_daily_report'],
  }

}
