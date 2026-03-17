# A Puppet manifest simulating configuration of an AWS RDS instance
# with weak encryption settings (conceptual for a Puppet-managed cloud resource).
# This demonstrates CWE-326.

# Note: In a real-world scenario, Puppet might use custom types or modules
# like 'puppetlabs-aws' to manage cloud resources directly.
# This example uses a fictional `cloud_rds_instance` resource to demonstrate
# the configuration attributes for CWE-326.

class cloud_db_encryption {
  cloud_rds_instance { 'my-weak-db-instance': # Fictional resource type
    ensure                         => present,
    db_instance_class              => 'db.t2.micro',
    engine                         => 'mysql',
    allocated_storage              => 20,
    db_name                        => 'mydb',
    master_username                => 'admin',
    master_user_password           => 'SuperSecretPa$$m0rd!', # Placeholder; would be from Hiera/Vault
    storage_encrypted              => true,
    # CWE-326: Weak Cryptographic Algorithms - AES-128 (when 256 is preferred for high security)
    storage_encryption_algorithm   => 'AES-128',
    kms_key_id                     => 'arn:aws:kms:us-east-1:123456789012:key/weak-kms-key', # Fictional KMS key
    # CWE-326: Outdated Protocols - TLSv1.0
    tls_minimum_version            => 'TLSv1.0',
  }
}

include cloud_db_encryption
