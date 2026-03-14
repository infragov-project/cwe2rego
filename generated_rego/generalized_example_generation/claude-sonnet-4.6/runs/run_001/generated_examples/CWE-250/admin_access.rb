file '/etc/sudoers.d/deploy_user' do
  content 'deploy_user ALL=(ALL) NOPASSWD: ALL'
  mode '0440'
end