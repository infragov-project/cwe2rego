# app_config_plaintext.rb

directory '/opt/my-app' do
  owner 'appuser'
  group 'appuser'
  mode '0755'
  recursive true
  action :create
end

file '/opt/my-app/config.properties' do
  owner 'appuser'
  group 'appuser'
  mode '0640'
  content <<-EOF
# Application Configuration
database.url=jdbc:mysql://localhost:3306/myapp
database.username=dbuser
database.password=plaintext_db_pass_123 # CWE-319
api.key=fajkfasjfbasfasfsbgsgfhghfgh # CWE-319
      EOF
  action :create
end
