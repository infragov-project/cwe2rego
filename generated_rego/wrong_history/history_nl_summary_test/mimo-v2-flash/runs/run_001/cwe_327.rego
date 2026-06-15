package glitch

import data.glitch_lib

weak_algorithm_pattern := "(?i)(DES|3DES|RC4|MD5|SHA1|AES[-_]?ECB|AES[-_]?128|RSA[-_]?1024|blowfish|SHA[-_]?1|SHA[-_]?1[-_]96|HMAC[-_]?SHA1)"
weak_mode_pattern := "(?i)(ECB|SSLv2|SSLv3|TLS1\\.0|TLS1\\.1)"
weak_key_lengths := {1024, 128, 64, 96}
weak_crypt_names := {"md5_crypt", "md5", "sha1", "des", "3des", "rc4", "password_md5"}
cryptographic_attributes_regex := "(?i).*(algorithm|cipher|encrypt|decrypt|hash|ssl|tls|key|mode|protocol|kdf|encoding|password|auth|crypto|signature|verification|prompt|encrypt).*"

check_weak_string(value) {
    value.ir_type == "String"
    regex.match(weak_algorithm_pattern, value.value)
} else {
    value.ir_type == "String"
    regex.match(weak_mode_pattern, value.value)
} else {
    value.ir_type == "String"
    lower_value := lower(value.value)
    weak_crypt_names[lower_value]
}

check_weak_integer(value) {
    value.ir_type == "Integer"
    weak_key_lengths[value.value]
}

check_node_for_weak_value(node) {
    node.ir_type == "String"
    check_weak_string(node)
} else {
    node.ir_type == "Integer"
    check_weak_integer(node)
} else {
    node.ir_type == "FunctionCall"
    check_weak_string({"ir_type": "String", "value": node.name})
} else {
    node.ir_type == "MethodCall"
    check_weak_string({"ir_type": "String", "value": node.method})
}

value_contains_weak_value(node) {
    check_node_for_weak_value(node)
} else {
    some path, child
    walk(node, [path, child])
    check_node_for_weak_value(child)
}

is_cryptographic_context(node) {
    node.ir_type == "Attribute"
    regex.match(cryptographic_attributes_regex, node.name)
} else {
    node.ir_type == "Variable"
    regex.match(cryptographic_attributes_regex, node.name)
} else {
    node.ir_type == "FunctionCall"
    regex.match(cryptographic_attributes_regex, node.name)
} else {
    node.ir_type == "MethodCall"
    regex.match(cryptographic_attributes_regex, node.method)
} else {
    node.ir_type == "KeyValue"
    regex.match(cryptographic_attributes_regex, node.name)
} else {
    node.ir_type == "String"
    regex.match(cryptographic_attributes_regex, node.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    is_cryptographic_context(n)
    n.ir_type == "Attribute"
    value_contains_weak_value(n.value)
    not n.name == "vars_prompt"
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Avoid using deprecated or weak cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    is_cryptographic_context(n)
    n.ir_type == "Variable"
    value_contains_weak_value(n.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Avoid using deprecated or weak cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    is_cryptographic_context(n)
    n.ir_type == "FunctionCall"
    check_weak_string({"ir_type": "String", "value": n.name})
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Avoid using deprecated or weak cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    is_cryptographic_context(n)
    n.ir_type == "FunctionCall"
    arg := n.args[_]
    value_contains_weak_value(arg)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Avoid using deprecated or weak cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    is_cryptographic_context(n)
    n.ir_type == "MethodCall"
    check_weak_string({"ir_type": "String", "value": n.method})
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Avoid using deprecated or weak cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    is_cryptographic_context(n)
    n.ir_type == "MethodCall"
    value_contains_weak_value(n.receiver)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Avoid using deprecated or weak cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    is_cryptographic_context(n)
    n.ir_type == "MethodCall"
    arg := n.args[_]
    value_contains_weak_value(arg)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Avoid using deprecated or weak cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    is_cryptographic_context(n)
    n.ir_type == "KeyValue"
    value_contains_weak_value(n.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Avoid using deprecated or weak cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "Hash"
    kv := n.value[_]
    key := kv.key
    value := kv.value
    regex.match(cryptographic_attributes_regex, key.value)
    value_contains_weak_value(value)
    result := {
        "type": "sec_weak_crypt",
        "element": value,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Avoid using deprecated or weak cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "Array"
    item := n.value[_]
    item.ir_type == "Hash"
    kv := item.value[_]
    key := kv.key
    value := kv.value
    regex.match(cryptographic_attributes_regex, key.value)
    value_contains_weak_value(value)
    result := {
        "type": "sec_weak_crypt",
        "element": value,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Avoid using deprecated or weak cryptographic algorithms. (CWE-327)"
    }
}