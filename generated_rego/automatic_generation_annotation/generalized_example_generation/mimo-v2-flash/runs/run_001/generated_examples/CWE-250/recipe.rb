execute 'run-migration' do
  command 'rails db:migrate'
  user 'root'
  action :run
end
