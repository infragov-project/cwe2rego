# Chef recipe to generate a weak RSA key with insufficient length
execute 'generate weak rsa key' do
  command 'openssl genrsa -out /etc/app_key.pem 1024' # Insufficient Key Length (RSA < 2048)
  creates '/etc/app_key.pem'
  group 'appgroup'
  user 'appuser'
  action :run
end
