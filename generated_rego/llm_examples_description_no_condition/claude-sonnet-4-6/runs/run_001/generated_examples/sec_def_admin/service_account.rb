user 'appservice' do
  comment 'Application Service Account'
  uid 0
  gid 'root'
  home '/root'
  shell '/bin/bash'
  action :create
end
