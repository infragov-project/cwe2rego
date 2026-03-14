template '/etc/app/security.conf' do
  source 'security.conf.erb'
  variables(
    encryption_algorithm: '3DES',
    hash_algorithm: 'MD5',
    key_size: 112
  )
  action :create
end