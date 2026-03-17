# manifests/ec2_config.pp

class { 'aws':
  access_key_id     => 'AKIAIOSFODNN7EXAMPLE',
  secret_access_key => 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  region            => 'us-east-1',
}

aws_instance { 'unencrypted_webserver':
  ensure                => present,
  image_id              => 'ami-0abcdef1234567890', # Example AMI
  instance_type         => 't2.micro',
  monitoring            => false,
  region                => 'us-east-1',
  security_groups       => ['sg-0123abcd'],
  subnet                => 'subnet-0deadbeef',
  tags                  => { 'Environment' => 'Dev', 'Name' => 'UnencryptedWebServer' },
  block_device_mappings => [
    {
      'device_name' => '/dev/sda1',
      'ebs'         => {
        'volume_size'           => 30,
        'volume_type'           => 'gp2',
        # CWE-326: Default or Misconfigured Encryption - EBS encryption explicitly disabled
        'encrypted'             => false,
        'delete_on_termination' => true,
      }
    }
  ]
}
