# Assumes a strongswan module (e.g., camptocamp/strongswan) is installed

class { 'strongswan': }

strongswan::conn { 'office-to-cloud':
  left        => '192.168.1.1',
  leftsubnet  => '192.168.1.0/24',
  right       => '203.0.113.1',
  rightsubnet => '10.0.0.0/16',
  ike_version => 'ikev2',
  # CWE-326: Deprecated or Weak Encryption Algorithms (DES, 3DES, SHA1, MD5)
  # CWE-326: Weak Key Length for DH groups (modp1024 maps to DH group 2, modp1536 maps to DH group 5)
  ike_proposals => [
    'des-sha1-modp1024', # DES for encryption, SHA1 for integrity, DH group 2
    '3des-md5-modp1536'  # 3DES for encryption, MD5 for integrity, DH group 5
  ],
  esp_proposals => [
    'des-sha1',
    '3des-md5'
  ],
  dpddelay    => '30',
  dpdtimeout  => '120',
  auto        => 'start',
}