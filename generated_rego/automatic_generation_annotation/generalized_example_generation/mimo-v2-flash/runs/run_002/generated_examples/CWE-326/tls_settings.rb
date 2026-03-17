node.default['app']['encryption']['algorithm'] = 'AES-128-CBC'
node.default['app']['encryption']['key'] = 'hardcoded_secret_key_12345'
node.default['app']['tls']['min_version'] = 'TLSv1.0'
node.default['app']['tls']['ciphers'] = 'RC4-SHA'