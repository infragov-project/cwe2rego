aws_iam_user 'deploy_user' do
  username 'administrator'
  path '/'
  action :create
end

aws_iam_policy 'admin_policy' do
  policy_name 'AdministratorAccess'
  policy_document({
    'Version' => '2012-10-17',
    'Statement' => [{
      'Effect'   => 'Allow',
      'Action'   => '*',
      'Resource' => '*'
    }]
  })
  action :create
end

aws_iam_user_policy 'attach_admin' do
  username 'administrator'
  policy_arn 'arn:aws:iam::aws:policy/AdministratorAccess'
  action :attach
end

user 'superuser' do
  comment 'System Super User'
  uid 0
  gid 'root'
  home '/root'
  shell '/bin/bash'
  action :create
end
