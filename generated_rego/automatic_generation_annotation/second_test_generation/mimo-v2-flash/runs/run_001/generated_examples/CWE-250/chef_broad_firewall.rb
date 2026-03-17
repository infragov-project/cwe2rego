# chef_broad_firewall.rb
# Requires the 'firewall' cookbook

firewall 'default' do
  action :enable
end

# Insecure rule: allows SSH from anywhere
firewall_rule 'open_ssh_globally' do
  port     22
  protocol :tcp
  source   '0.0.0.0/0' # Unrestricted access from anywhere - CWE-250
  command  :allow
end

# Insecure rule: allows HTTP from anywhere
firewall_rule 'open_http_globally' do
  port     80
  protocol :tcp
  source   '0.0.0.0/0' # Unrestricted access from anywhere - CWE-250
  command  :allow
end
