package glitch

import data.glitch_lib

sensitive_keywords := {"password", "passwd", "pwd", "secret", "token", "access_key", "api_key", "admin_password", "db_password", "root_password", "default_password", "key", "sha512_password"}

connection_string_patterns := [
    `(?i)["'][A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>?]*?(?:password|pwd)["']\s*[=:]\s*["'][^"'\n]{3,}["']`,
    `(?i)(?:secret|password|token)\s*[=:]\s*["'][^"'\n]{3,}["']`
]

find_sensitive_in_hash(hash_node) = result {
    hash_node.ir_type == "Hash"
    kv_pair = hash_node.value[_]
    kv_pair.key.ir_type == "String"
    key_name = lower(kv_pair.key.value)
    sensitive_keywords[key_name]
    kv_pair.value.ir_type == "String"
    count(kv_pair.value.value) > 3
    result = {"element": kv_pair.value, "key": key_name}
}

find_sensitive_in_array(array_node) = result {
    array_node.ir_type == "Array"
    item = array_node.value[_]
    item.ir_type == "Hash"
    result = find_sensitive_in_hash(item)
}

find_sensitive_flat(node) = result {
    node.ir_type == "Hash"
    result = find_sensitive_in_hash(node)
} else {
    node.ir_type == "Array"
    result = find_sensitive_in_array(node)
}

Glitch_Analysis[result] {
    parent = glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units = glitch_lib.all_atomic_units(parent)
    node = atomic_units[_]
    attrs = glitch_lib.all_attributes(node)
    attr = attrs[_]

    sensitive_keywords[lower(attr.name)]
    attr.value.ir_type == "String"
    count(attr.value.value) > 3

    result = {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Hardcoded password or secret found in IaC script - Avoid embedding plaintext credentials directly in configuration. Use secure mechanisms such as secret managers. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent = glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars = glitch_lib.all_variables(parent)
    var = vars[_]

    var.value.ir_type == "String"
    count(var.value.value) > 3
    sensitive_keywords[lower(var.name)]

    result = {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Hardcoded password or secret found in variable definition - Avoid using plaintext credentials in variables. Use dynamic secret retrieval instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent = glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars = glitch_lib.all_variables(parent)
    var = vars[_]
    
    var.value.ir_type == "Hash"
    hash_result = find_sensitive_in_hash(var.value)

    result = {
        "type": "sec_hard_pass",
        "element": hash_result.element,
        "path": parent.path,
        "description": "Hardcoded password or secret found in nested structure - Avoid embedding plaintext credentials in nested configurations. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent = glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars = glitch_lib.all_variables(parent)
    var = vars[_]
    
    var.value.ir_type == "Array"
    array_result = find_sensitive_in_array(var.value)

    result = {
        "type": "sec_hard_pass",
        "element": array_result.element,
        "path": parent.path,
        "description": "Hardcoded password or secret found in nested structure - Avoid embedding plaintext credentials in nested configurations. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent = glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars = glitch_lib.all_variables(parent)
    var = vars[_]
    
    flat_result = find_sensitive_flat(var.value)

    result = {
        "type": "sec_hard_pass",
        "element": flat_result.element,
        "path": parent.path,
        "description": "Hardcoded password or secret found in structured data - Avoid embedding plaintext credentials in complex data structures. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent = glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    some node
    walk(parent, [_, node])
    node.ir_type == "String"
    val = node.value
    pattern = connection_string_patterns[_]
    regex.match(pattern, val, _)

    result = {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Embedded credential detected in string literal, possibly a connection URI - Do not embed secrets in URLs or configuration strings. (CWE-259)"
    }
}