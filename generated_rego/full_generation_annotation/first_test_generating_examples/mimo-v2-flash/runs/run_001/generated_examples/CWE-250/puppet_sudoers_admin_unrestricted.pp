sudo::conf { 'admin_commands':
  content => '%admin ALL=(ALL) NOPASSWD: ALL',
  order   => 10,
}
