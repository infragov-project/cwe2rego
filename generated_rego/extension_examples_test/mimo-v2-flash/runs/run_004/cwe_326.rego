package glitch

import data.glitch_lib

weak_hashes := {"md5", "sha1", "sha-1"}
weak_algorithms := {"des", "3des", "triple_des", "rc4", "arcfour", "rsa-1024", "rsa-512", "ecdsa-sha1", "aes-128"}
outdated_protocols := {"ssl_v2", "ssl_v3", "tls_1_0", "tls_1_1"}
weak_ciphers := {"rc4", "des-cbc3-sha", "md5", "sha1", "cbc-mode", "aes-128"}
weak_policies := {"legacy", "insecure", "2016-08"}

check_weak_hash(value) {
    is_string(value)
    regex.match("(md5|sha1|sha-1)", lower(value))
}

check_weak_algorithm(value) {
    is_string(value)
    regex.match("(des|3des|triple_des|rc4|arcfour|rsa-1024|rsa-512|ecdsa-sha1|aes-128)", lower(value))
}

check_outdated_protocol(value) {
    is_string(value)
    regex.match("(ssl_v2|ssl_v3|tls_1_0|tls_1_1)", lower(value))
}

check_weak_cipher(value) {
    is_string(value)
    regex.match("(rc4|des-cbc3-sha|md5|sha1|cbc-mode|aes-128)", lower(value))
}

check_hardcoded_key(name, value) {
    is_string(name)
    is_string(value)
    regex.match("(password|key|secret|token|credential)", lower(name))
    value != ""
    not startswith(value, "${")
    not regex.match("{{.*}}", value)
}

check_weak_policy(value) {
    is_string(value)
    regex.match("(legacy|insecure|2016-08)", lower(value))
}

check_key_size(value) {
    is_number(value)
    value < 128
} else {
    is_string(value)
    regex.match("^[0-9]+$", value)
    to_number(value) < 128
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    regex.match("hash", lower(node.name))
    some arg
    node.args[arg]
    arg.ir_type == "String"
    check_weak_hash(arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of deprecated hash function - Avoid using MD5, SHA1 for cryptographic operations. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    regex.match("(encrypt|algorithm)", lower(node.name))
    node.value.ir_type == "String"
    check_weak_hash(node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of deprecated hash function - Avoid using MD5, SHA1 for cryptographic operations. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    regex.match("(encrypt|algorithm)", lower(node.name))
    node.value.ir_type == "String"
    check_weak_algorithm(node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak encryption algorithm - Avoid using weak cryptographic algorithms. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Variable"
    regex.match("(cipher|suite)", lower(node.name))
    node.value.ir_type == "String"
    check_weak_cipher(node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of insecure cipher suite - Avoid using weak cipher suites. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    regex.match("(key_size|key_length|bits)", lower(node.name))
    check_key_size(node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Insufficient key size - Use adequate key sizes. (CWE-326)"
    }
}