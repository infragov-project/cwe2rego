# Create user with a weak, easily crackable password hash
user 'weakuser_chef' do
  comment 'User with weak password hash'
  # CWE-326: Inadequate Encryption Strength (MD5 hash for password storage is insecure).
  # Using $1$ prefix for MD5.
  password '$1$weakSalt$P1g0oG860fC.pD.f.1YgA/' # Example MD5 hash
  home '/home/weakuser_chef'
  shell '/bin/bash'
  action :create
end