package glitch

import data.glitch_lib

weak_algorithms := {"DES", "3DES", "TripleDES", "RC4", "MD5", "SHA1", "SHA-1", "ECB", "SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}

check_weak_algorithm(value) {
    is_string(value)
    algorithm := weak_algorithms[_]
    regex.match(sprintf("(?i).*%s.*", [algorithm]), value)
    not is_file_path(value)
    not is_package_name(value)
}

is_file_path(value) {
    startswith(value, "/")
}

is_package_name(value) {
    regex.match("^[a-z0-9-]+$", value)
}

check_weak_algorithm_in_function(node) {
    node.ir_type == "FunctionCall"
    algorithm := weak_algorithms[_]
    regex.match(sprintf("(?i).*%s.*", [algorithm]), node.name)
}

check_weak_algorithm_in_args(node) {
    node.ir_type == "FunctionCall"
    algorithm := weak_algorithms[_]
    arg := node.args[_]
    arg.ir_type == "String"
    regex.match(sprintf("(?i).*%s.*", [algorithm]), arg.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "String"
    check_weak_algorithm(node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm or protocol - Avoid using deprecated algorithms like DES, MD5, or protocols like SSLv3, TLSv1.0. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    check_weak_algorithm_in_function(node)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm or protocol - Avoid using deprecated algorithms like DES, MD5, or protocols like SSLv3, TLSv1.0. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    check_weak_algorithm_in_args(node)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm or protocol - Avoid using deprecated algorithms like DES, MD5, or protocols like SSLv3, TLSv1.0. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    key_size_names := {"key_size", "key_length"}
    attr.name == key_size_names[_]
    attr.value.ir_type == "Integer"
    attr.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak cryptographic key size - Key size should be at least 2048 bits for asymmetric keys. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    node.name != "shell"
    node.name != "command"
    node.name != "args"
    check_weak_algorithm(node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm or protocol - Avoid using deprecated algorithms like DES, MD5, or protocols like SSLv3, TLSv1.0. (CWE-327)"
    }
}