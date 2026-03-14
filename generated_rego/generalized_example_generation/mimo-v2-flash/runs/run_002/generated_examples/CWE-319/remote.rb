remote_file '/tmp/package.deb' do
  source 'http://archive.example.com/package.deb'
  action :create
end
