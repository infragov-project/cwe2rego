bash 'install_custom_tool' do
  code <<-EOF
  wget http://internal/tool.tar.gz
  tar -xzf tool.tar.gz
  EOF
  user 'root'
  cwd '/tmp'
end