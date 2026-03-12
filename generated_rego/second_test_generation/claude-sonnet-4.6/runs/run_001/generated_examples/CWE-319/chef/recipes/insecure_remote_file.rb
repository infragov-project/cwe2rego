# Recipe to download a file, bypassing SSL verification
remote_file '/opt/insecure_app.zip' do
  source 'https://insecure.example.com/app.zip' # HTTPS used, but verification bypassed
  ssl_verify_mode :none # Explicitly disable SSL verification
  action :create
end
