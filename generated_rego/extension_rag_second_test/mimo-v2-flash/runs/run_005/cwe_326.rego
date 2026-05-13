package glitch

import data.glitch_lib

weak_algorithms := {"DES", "3DES", "RC4", "AES-128", "Blowfish", "SHA-1", "MD5", "md5_crypt"}
weak_key_lengths := {1024, 160, 128}
weak_protocols := {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
weak_cipher_patterns := {"DES", "3DES", "RC4", "MD5", "NULL", "EXPORT", "CBC", "SHA1"}
weak_custom_values := {"custom", "proprietary", "xor", "base64"}

check_weak_string(str) {
    str in weak_algorithms
}

check_weak_string(str) {
    str in weak_protocols
}

check_weak_string(str) {
    str in weak_custom_values
}

check_weak_string(str) {
    pattern := weak_cipher_patterns[_]
    regex.match(sprintf("(?i).*%s.*", [pattern]), str)
}

check_weak_integer(num) {
    num in weak_key_lengths
}

has_weak_value(value) {
    walk(value, [path, node])
    node.ir_type == "String"
    check_weak_string(node.value)
}

has_weak_value(value) {
    walk(value, [path, node])
    node.ir_type == "Integer"
    check_weak_integer(node.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    has_weak_value(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption configuration in attribute (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    has_weak_value(var.value)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Weak encryption configuration in variable (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.ir_type == "FunctionCall"
    check_weak_string(node.name)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak encryption function call (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.ir_type == "FunctionCall"
    some i
    arg := node.args[i]
    has_weak_value(arg)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak encryption in function argument (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "shell"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "shell"
    has_weak_value(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption in shell command (CWE-326)"
    }
}