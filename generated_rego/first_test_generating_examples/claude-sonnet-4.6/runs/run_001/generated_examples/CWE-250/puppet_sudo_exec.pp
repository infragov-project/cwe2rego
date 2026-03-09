# Class: my_module::sudo_exec 

class my_module::sudo_exec { 
  exec { 'run_sudo_command': 
    command => '/usr/bin/sudo /bin/touch /var/run/privileged_socket.sock', 
    path    => '/usr/bin:/bin', 
  } 
}