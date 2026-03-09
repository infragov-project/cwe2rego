# chef_excessive_perms.rb
# Recipe to create resources with overly permissive access

# WEAKNESS: Directory with world-writable permissions
directory '/var/www/html/app_data' do
  owner 'www-data'
  group 'www-data'
  mode '0777' # WEAKNESS: World-writable directory
  action :create
end

# WEAKNESS: File with world-readable/writable permissions for sensitive data
file '/etc/app_config/database_credentials.conf' do
  owner 'appuser'
  group 'appuser'
  mode '0666' # WEAKNESS: World-readable/writable file, especially for credentials.
  sensitive true # Indicates this is sensitive data, making the permission a greater weakness.
  action :create
  content 'username=dbadmin;password=supersecret'
end

# WEAKNESS: Publicly accessible S3 bucket configuration (conceptual example in Chef)
# While not direct file permissions, this relates to 'Resource Access Controls'
# and is an excessive permission for a resource.
# This block would typically use a cloud provider gem, but conceptually shows the weakness.
# aws_s3_bucket 'my-public-bucket' do
#   bucket_name 'my-sensitive-public-bucket-12345'
#   acl 'public-read-write' # WEAKNESS: Public read/write access to a bucket.
#   action :create
# end
