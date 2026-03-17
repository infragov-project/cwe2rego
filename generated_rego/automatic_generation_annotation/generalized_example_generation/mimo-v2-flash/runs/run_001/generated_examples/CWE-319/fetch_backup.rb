remote_file '/var/backups/data.zip' do
  source 'http://storage.internal/data.zip'
  action :create
  headers 'Authorization' => "Basic #{credentials}"
end