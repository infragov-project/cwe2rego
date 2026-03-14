yum_repository 'custom-repo' do
  baseurl 'http://repo.internal.local/packages'
  gpgcheck false
  sslverify false
  action :create
end