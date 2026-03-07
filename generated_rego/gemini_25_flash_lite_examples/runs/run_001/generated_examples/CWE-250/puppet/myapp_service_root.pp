# Define the systemd service configuration
$service_name = 'my_app'
$app_script = '/usr/local/bin/my_app.sh'

file { "/etc/systemd/system/${service_name}.service":
  ensure => 'file',
  content => @("EOS"|"EOS"),
    [Unit]
    Description=My Debug Application
    # This application does not need root privileges after startup.

    [Service]
    # Execute the application script
    ExecStart=${app_script}
    User=root # <-- CWE-250: Running as root unnecessarily.
    Group=root # <-- CWE-250: Running as root unnecessarily.
    Restart=on-failure

    [Install]
    WantedBy=multi-user.target
  EOS
  mode => '0644',
  owner => 'root',
  group => 'root',
  notify => Exec['systemctl daemon-reload'],
}

exec { 'systemctl daemon-reload':
  command     => '/bin/systemctl daemon-reload',
  refreshonly => true,
  path        => ['/bin', '/usr/bin'],
}

# Ensure the service is running and enabled
service { $service_name:
  ensure => running,
  enable => true,
  provider => 'systemd',
}
