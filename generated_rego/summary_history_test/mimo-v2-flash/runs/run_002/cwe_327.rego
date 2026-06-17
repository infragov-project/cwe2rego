package glitch

import data.glitch_lib

weak_algorithm_set := {"des", "3des", "rc4", "md5", "sha1", "sha-1", "ssl", "tls_1_0", "tls_1_1", "rsa_1024", "ecdsa_sha1", "pbkdf1", "md5_crypt"}
key_size_attributes := {"key_length", "key_size"}
protocol_attributes := {"ssl_policy", "min_tls_version", "protocol_version"}
weak_protocols := {"ssl", "tls_1_0", "tls_1_1"}
mode_attributes := {"encryption_mode"}
weak_modes := {"ecb", "cbc"}
custom_attributes := {"crypto_provider", "algorithm_source"}
hashing_attributes := {"hashing_algorithm", "hash_type", "digest_algorithm", "encrypt"}
weak_hashing := {"md5", "sha1", "sha-1", "md5_crypt"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "String"
    lower_value := lower(node.value)
    weak_algorithm_set[lower_value]
    parent_node := find_parent(parent, path)
    is_cryptographic_context(parent_node)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak cryptographic algorithm - Avoid using broken cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    lower_name := lower(node.name)
    regex.match(".*(hash|encrypt|decrypt|sign|verify|cipher|mac|filter).*", lower_name)
    arg := node.args[_]
    arg.ir_type == "String"
    lower_arg := lower(arg.value)
    weak_algorithm_set[lower_arg]
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak cryptographic algorithm - Avoid using broken cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Access"
    node.right.ir_type == "String"
    lower_value := lower(node.right.value)
    weak_algorithm_set[lower_value]
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak cryptographic algorithm - Avoid using broken cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    lower_name := lower(node.name)
    hashing_attributes[lower_name]
    node.value.ir_type == "String"
    lower_value := lower(node.value.value)
    weak_hashing[lower_value]
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak hashing algorithm - Avoid using MD5 or SHA1 for sensitive data. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    lower_name := lower(node.name)
    hashing_attributes[lower_name]
    node.value.ir_type == "Access"
    node.value.right.ir_type == "String"
    lower_value := lower(node.value.right.value)
    regex.match(".*password_md5.*", lower_value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak hashing algorithm - Avoid using MD5 or SHA1 for sensitive data. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    pair.key.ir_type == "String"
    pair.value.ir_type == "String"
    lower_key := lower(pair.key.value)
    lower_value := lower(pair.value.value)
    lower_key == "encrypt"
    weak_hashing[lower_value]
    result := {
        "type": "sec_weak_crypt",
        "element": pair.value,
        "path": parent.path,
        "description": "Use of weak hashing algorithm - Avoid using MD5 or SHA1 for sensitive data. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower_name := lower(attr.name)
    key_size_attributes[lower_name]
    attr.value.ir_type == "Integer"
    attr.value.value < 256
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate key size - Use of weak key sizes in cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower_name := lower(attr.name)
    key_size_attributes[lower_name]
    attr.value.ir_type == "Integer"
    attr.value.value == 512
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate key size - Use of weak key sizes in cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower_name := lower(attr.name)
    key_size_attributes[lower_name]
    attr.value.ir_type == "Integer"
    attr.value.value == 768
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate key size - Use of weak key sizes in cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower_name := lower(attr.name)
    key_size_attributes[lower_name]
    attr.value.ir_type == "Integer"
    attr.value.value == 1024
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate key size - Use of weak key sizes in cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower_name := lower(attr.name)
    key_size_attributes[lower_name]
    attr.value.ir_type == "String"
    is_number(attr.value.value)
    key_val := to_number(attr.value.value)
    key_val < 256
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate key size - Use of weak key sizes in cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower_name := lower(attr.name)
    key_size_attributes[lower_name]
    attr.value.ir_type == "String"
    is_number(attr.value.value)
    key_val := to_number(attr.value.value)
    key_val == 512
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate key size - Use of weak key sizes in cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower_name := lower(attr.name)
    key_size_attributes[lower_name]
    attr.value.ir_type == "String"
    is_number(attr.value.value)
    key_val := to_number(attr.value.value)
    key_val == 768
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate key size - Use of weak key sizes in cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower_name := lower(attr.name)
    key_size_attributes[lower_name]
    attr.value.ir_type == "String"
    is_number(attr.value.value)
    key_val := to_number(attr.value.value)
    key_val == 1024
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate key size - Use of weak key sizes in cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower_name := lower(attr.name)
    protocol_attributes[lower_name]
    attr.value.ir_type == "String"
    normalized_value := replace(replace(lower(attr.value.value), " ", "_"), "-", "_")
    weak_protocols[normalized_value]
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak protocol - Avoid using deprecated protocols like SSL or TLS 1.0/1.1. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower_name := lower(attr.name)
    mode_attributes[lower_name]
    attr.value.ir_type == "String"
    lower_value := lower(attr.value.value)
    weak_modes[lower_value]
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak encryption mode - Avoid using ECB or CBC without authentication. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower_name := lower(attr.name)
    custom_attributes[lower_name]
    attr.value.ir_type == "String"
    lower_value := lower(attr.value.value)
    regex.match(".*(custom|proprietary).*", lower_value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Custom cryptographic implementation - Avoid using non-standard or non-vetted cryptographic implementations. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower_name := lower(attr.name)
    hashing_attributes[lower_name]
    attr.value.ir_type == "String"
    lower_value := lower(attr.value.value)
    weak_hashing[lower_value]
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak hashing algorithm - Avoid using MD5 or SHA1 for sensitive data. (CWE-327)"
    }
}

is_cryptographic_context(node) {
    node.ir_type == "Attribute"
    lower_name := lower(node.name)
    regex.match(".*(algorithm|hash|encrypt|decrypt|cipher|protocol|mode|key|signature|mac|digest|ssl|tls|rsa|ecdsa|pbkdf|des|3des|rc4|md5|sha).*", lower_name)
} else {
    node.ir_type == "FunctionCall"
    lower_name := lower(node.name)
    regex.match(".*(hash|encrypt|decrypt|sign|verify|cipher|mac).*", lower_name)
} else {
    node.ir_type == "Variable"
    lower_name := lower(node.name)
    regex.match(".*(algorithm|hash|encrypt|decrypt|cipher|protocol|mode|key|signature|mac|digest|ssl|tls|rsa|ecdsa|pbkdf|des|3des|rc4|md5|sha).*", lower_name)
} else {
    node.ir_type == "Access"
    node.right.ir_type == "String"
    lower_value := lower(node.right.value)
    regex.match(".*(algorithm|hash|encrypt|decrypt|cipher|protocol|mode|key|signature|mac|digest|ssl|tls|rsa|ecdsa|pbkdf|des|3des|rc4|md5|sha).*", lower_value)
}

find_parent(node, path) = parent {
    count(path) > 0
    parent_path := array.slice(path, 0, count(path)-1)
    walk(node, [parent_path, parent])
} else = node {
    node
}