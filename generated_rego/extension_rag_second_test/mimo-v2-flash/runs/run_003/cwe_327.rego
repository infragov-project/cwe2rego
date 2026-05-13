package glitch

import data.glitch_lib

# CWE-327: Broken or Risky Cryptography
# Detects weak algorithms, key sizes, and modes in IaC configurations.

# 1. Detect weak algorithms in String values (Ansible, Chef, Puppet)
# Covers Ansible vars_prompt encrypt, Chef cipher_suites, and generic string attributes.
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Walk to find String nodes
    walk(parent, [_, node])
    node.ir_type == "String"
    
    # Regex for weak crypto algorithms and modes
    # Covers: MD5, SHA1, DES, 3DES, RC4, ECB, SSLv2, SSLv3, TLS_1_0, TLS_1_1, md5_crypt
    regex.match("(?i)(md5|sha1|sha-1|des|3des|rc4|ecb|sslv2|sslv3|tls_1_0|tls_1_1|md5_crypt)", node.value)
    
    # Exclude false positives (e.g., file paths, comments)
    not regex.match("(?i)(path|file|directory|home|tmp|var|comment)", node.value)

    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm (CWE-327)"
    }
}

# 2. Detect weak key sizes in Attribute or Variable nodes (Ansible, Chef, Puppet)
# Covers key_size, key_length, rsa_bits, etc.
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    
    # Check for key size attributes
    regex.match("(?i)(key_size|key_length|rsa_bits|dsa_bits)", node.name)
    
    # Check if value is an integer less than 2048
    node.value.ir_type == "Integer"
    node.value.value < 2048

    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of insufficient key length (CWE-327)"
    }
}

# 3. Detect insecure cryptographic mode (ECB) in Attribute nodes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    
    # Check for mode attribute
    regex.match("(?i)(mode|block_mode)", node.name)
    
    # Check if value is ECB
    node.value.ir_type == "String"
    node.value.value == "ECB"

    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of insecure cryptographic mode (CWE-327)"
    }
}

# 4. Detect weak password hashing in Ansible vars_prompt (encrypt attribute)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    node.name == "encrypt"
    node.value.ir_type == "String"
    regex.match("(?i)(md5_crypt|sha1|des|3des)", node.value.value)

    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak password hashing algorithm (CWE-327)"
    }
}

# 5. Detect weak cipher suites in Chef attributes (cipher_suites)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Variable"
    
    # Check for cipher_suites attribute
    regex.match("(?i)(cipher_suites|ssl_ciphers)", node.name)
    
    # Check if value contains weak ciphers (e.g., TLS_RSA_WITH_AES_128_CBC_SHA)
    node.value.ir_type == "String"
    regex.match("(?i)(TLS_RSA_WITH_AES_128|TLS_RSA_WITH_AES_256|CBC_SHA)", node.value.value)

    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak cipher suite (CWE-327)"
    }
}

# 6. Detect weak hash functions in FunctionCall arguments (Ansible hash filter)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    
    # Check if function name indicates crypto operation
    regex.match("(?i)(hash|md5|sha1|openssl|enc)", node.name)
    
    # Check arguments for weak algorithms
    some i
    arg := node.args[i]
    arg.ir_type == "String"
    regex.match("(?i)(md5|sha1|des|3des|rc4|ecb)", arg.value)

    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm (CWE-327)"
    }
}