# modules/users/manifests/app_user.pp
class user::app_user {
  user { 'appuser_insecure':
    ensure     => present,
    uid        => '1001',
    shell      => '/bin/bash',
    home       => '/home/appuser_insecure',
    password   => 'plaintext_user_password!', # CWE-319: Hardcoded plaintext password
    managehome => true,
  }
}

# In site.pp or another top-level manifest:
# include user::app_user
