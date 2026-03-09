# Class: my_module::root_exec 

class my_module::root_exec { 
  exec { 'create_root_file': 
    command => '/bin/echo "Hello from Puppet root" > /root/puppet-test.txt', 
    user    => 'root', 
    path    => '/usr/bin:/bin', 
  } 
}