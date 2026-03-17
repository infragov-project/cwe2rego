# file: overly_permissive_sudo.pp
# This manifest grants a user overly broad sudo access using the 'sudo' module.

user { 'admin_user':
  ensure   => present,
  password => '$6$salt$hashedpassword', # Example password
  comment  => 'Admin User with broad privileges',
}

# CWE-250: grants NOPASSWD ALL commands to admin_user, violating least privilege principle.
sudo::rule { 'admin_user_sudo':
  user     => 'admin_user',
  cmnd     => ['ALL'],
  nopasswd => true,
}