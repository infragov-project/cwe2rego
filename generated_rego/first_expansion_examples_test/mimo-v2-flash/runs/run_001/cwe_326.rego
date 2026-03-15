package glitch

import data.glitch_lib

weak_strings := {"des", "3des", "rc4", "rc2", "blowfish", "aes-128", "md5", "sha1", "none", "disabled", "sslv2", "sslv3", "tls1.0", "tls1.1", "latest"}
weak_integers := {1024, 56, 64}

contains_weak_pattern(str) {
    pattern := weak_strings[_]
    regex.match(sprintf("(?i).*%s.*", [pattern]), str)
}

check_value_weak(value) {
    value.ir_type == "String"
    contains_weak_pattern(value.value)
} else {
    value.ir_type == "Integer"
    value.value == weak_integers[_]
} else {
    value.ir_type == "FunctionCall"
    check_function_weak(value)
} else {
    value.ir_type == "Access"
    value.right.ir_type == "String"
    contains_weak_pattern(value.right.value)
}

check_function_weak(func) {
    contains_weak_pattern(func.name)
} else {
    count([arg | arg := func.args[_]; arg.ir_type == "String"; contains_weak_pattern(arg.value)]) > 0
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    check_value_weak(attr.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak encryption detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    check_value_weak(var.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak encryption detected in variable. (CWE-326)"
    }
}