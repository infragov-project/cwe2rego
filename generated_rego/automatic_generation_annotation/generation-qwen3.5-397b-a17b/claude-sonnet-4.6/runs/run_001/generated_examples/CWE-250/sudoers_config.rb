template '/etc/sudoers.d/deployers' do
  source 'sudoers.erb'
  mode '0440'
  owner 'root'
  group 'root'
  variables({
    users: ['deploy', 'jenkins'],
    rules: ['ALL=(ALL) NOPASSWD: ALL']
  })
end

file '/etc/sudoers.d/admins' do
  content '%wheel ALL=(ALL) NOPASSWD: ALL
'
  mode '0440'
  owner 'root'
  group 'root'
  action :create
end