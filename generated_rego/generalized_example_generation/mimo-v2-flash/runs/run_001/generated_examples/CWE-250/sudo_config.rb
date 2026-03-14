sudo 'admin_privileges' do
  user 'deployer'
  commands ['ALL']
  host 'ALL'
  run_as 'ALL'
end
