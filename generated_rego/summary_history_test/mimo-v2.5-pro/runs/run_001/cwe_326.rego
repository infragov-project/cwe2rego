package glitch

import data.glitch_lib

# Weak cryptographic algorithm names (lowercase, for exact matching of string values)
weak_algorithms := {"md5_crypt", "md5crypt", "md5", "sha1", "sha-1", "sha_1", "sha128", "ripemd160", "des", "3des", "rc4", "rc2", "idea", "blowfish", "arcfour", "crypt", "des_crypt", "hmac-md5", "hmac-sha1-96", "diffie-hellman-group1-sha1", "ssl3", "tls1", "tls1.0", "tls1.1", "tls1_0", "tls1_1"}

# Pattern for detecting weak TLS/SSL cipher suites and weak cipher names
weak_cipher_pattern := `(?i)((TLS|SSL)_[A-Z0-9_]*(_CBC_|_RC4_|_RC2_|_NULL_|_EXPORT_|WITH_DES_|WITH_3DES_)[A-Z0-9_]*|DES-CBC3|DES-CBC-|RC4-|NULL-|EXPORT-|3DES-|RC2-CBC)`

# Weak key lengths for RSA/DSA
weak_key_lengths := {512, 768, 1024}

# Attribute/Variable names related to key lengths
key_length_pattern := `(?i)(key.?size|key.?length|key.?bits|keysize|keylength|keybits)`

# Pattern for weak algorithm names as components of compound identifiers
weak_algo_component_pattern := `(?i)(^|[_\-.])(md5_crypt|md5crypt|des_crypt|hmac-md5|hmac-sha1-96|md5|sha1|sha-1|sha_1|3des|des|rc4|rc2|arcfour|ripemd160|blowfish|idea|crypt|ssl3|tls1\.0|tls1\.1|tls1_0|tls1_1)($|[_\-.])`

# Check if a string exactly matches a weak algorithm name (case-insensitive)
is_weak_algorithm(value) {
    weak_algorithms[lower(trim_space(value))]
}

# Check if a string contains a weak algorithm name as a component of a compound identifier
contains_weak_algo(value) {
    regex.match(weak_algo_component_pattern, value)
}

# Detect String values that exactly match weak algorithm names anywhere in the IR tree
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "String"
    is_weak_algorithm(node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak cryptographic algorithm or protocol used. (CWE-326)"
    }
}

# Detect FunctionCall names matching weak algorithm names
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    is_weak_algorithm(node.name)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak cryptographic algorithm function call used. (CWE-326)"
    }
}

# Detect weak algorithm references in Access node keys (e.g. data['password_md5'])
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Access"
    node.right.ir_type == "String"
    contains_weak_algo(node.right.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate encryption strength - Reference to weak cryptographic algorithm in data access. (CWE-326)"
    }
}

# Detect weak cipher suites in String values
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "String"
    regex.match(weak_cipher_pattern, node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak cipher suite used. (CWE-326)"
    }
}

# Detect weak key lengths in Attribute/Variable values
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    regex.match(key_length_pattern, node.name)
    node.value.ir_type == "Integer"
    weak_key_lengths[node.value.value]
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak key length used. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    regex.match(key_length_pattern, node.name)
    node.value.ir_type == "Integer"
    weak_key_lengths[node.value.value]
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak key length used. (CWE-326)"
    }
}