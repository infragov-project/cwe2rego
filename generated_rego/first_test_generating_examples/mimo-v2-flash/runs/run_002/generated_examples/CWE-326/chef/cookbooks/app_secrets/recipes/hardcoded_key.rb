# Chef recipe to store a hard-coded encryption key directly in IaC
file '/etc/myapp/encryption_key.txt' do
  content 'V3ryS3cr3tHardc0d3dK3y!' # Inadequate Key Management (Hard-coded encryption key)
  owner 'root'
  group 'root'
  mode '0600'
end
