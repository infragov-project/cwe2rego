package glitch

import data.glitch_lib

is_password_field_empty(name) {
    regex.match(`(?i).*(password|passwd|pwd|passphrase|secret|credential|activationkey).*`, name)
    not regex.match(`(?i).*(secret[._-]?key|public[._-]?key|private[._-]?key|ssh[._-]?key|host[._-]?key|signing[._-]?key|encryption[._-]?key|key[._-]?(name|pair|id|ring|store|file|path|type|size)).*`, name)
}

is_password_field_null(name) {
    not regex.match(`\[`, name)
    regex.match(`(?i).*(password|passwd|pwd|passphrase|secret|credential).*`, name)
    not regex.match(`(?i).*(secret[._-]?key|public[._-]?key|private[._-]?key|ssh[._-]?key|signing[._-]?key|key[._-]?(name|pair|id|ring|store|file|path|type|size)).*`, name)
}

is_password_field_null(name) {
    regex.match(`\[`, name)
    regex.match(`(?i).*\[["'](password|passwd|pwd|passphrase)["']\]$`, name)
}

is_empty_string(value) {
    value.ir_type == "String"
    regex.match(`^\s*$`, value.value)
}

is_null_undef(value) {
    value.ir_type == "Null"
}

is_null_undef(value) {
    value.ir_type == "Undef"
}

var_has_empty_default_in_code(var_name, code) {
    pattern := concat("", [`(?i)\$`, var_name, `\s*=\s*(?:''|"")`])
    regex.match(pattern, code)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_password_field_empty(attr.name)
    is_empty_string(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration - Password fields should not be empty or null. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_password_field_null(attr.name)
    is_null_undef(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration - Password fields should not be empty or null. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_password_field_empty(v.name)
    is_empty_string(v.value)
    result := {
        "type": "sec_empty_pass",
        "element": v,
        "path": parent.path,
        "description": "Empty password in configuration - Password fields should not be empty or null. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_password_field_null(v.name)
    is_null_undef(v.value)
    result := {
        "type": "sec_empty_pass",
        "element": v,
        "path": parent.path,
        "description": "Empty password in configuration - Password fields should not be empty or null. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match(`(?i).*(pwd|password|pass)=\s*(;|&|,|$)`, attr.value.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in connection string - Connection strings should not contain empty password segments. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_password_field_empty(attr.name)
    attr.value.ir_type == "FunctionCall"
    arg := attr.value.args[_]
    arg.ir_type == "VariableReference"
    var_has_empty_default_in_code(arg.value, parent.code)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration - Password fields should not be empty or null. (CWE-258)"
    }
}