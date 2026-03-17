remote_file '/etc/secrets/config' do
  source 'http://internal-repo.example.com/secrets/config'
  action :create
end
