apt_repository 'nginx-source' do
  uri 'http://nginx.org/packages/ubuntu'
  distribution 'bionic'
  components ['nginx']
  action :add
end
