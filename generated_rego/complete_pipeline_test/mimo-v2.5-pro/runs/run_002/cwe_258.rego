package glitch

import data.glitch_lib

is_empty(value) {
    value.ir_type == "String"
    value.value == ""
} else {
    value.ir_type == "Null"
} else {
    value.ir_type == "Undef"
} else {
    value.ir_type == "String"
    regex.match(`^\s*$`, value.value)
}

service_prefixes := {"proxy", "cache", "api"}

has_service_prefix(name) {
    prefix := service_prefixes[_]
    regex.match(sprintf(`(?i)(^|[_.'\[\]\s-])%s([_.'\[\]\s-]|$)`, [prefix]), name)
}

is_credential_field(name) {
    regex.match(`(?i)password|passwd`, name)
    not has_service_prefix(name)
} else {
    regex.match(`(?i)secret`, name)
    not has_service_prefix(name)
} else {
    regex.match(`(?i)token`, name)
    not has_service_prefix(name)
} else {
    regex.match(`(?i)key$`, name)
    not has_service_prefix(name)
} else {
    regex.match(`(?i)(^|[_.'\[\]\s-])pass$`, name)
    not has_service_prefix(name)
} else {
    regex.match(`(?i)credentials`, name)
    not has_service_prefix(name)
}

check_empty_credential_value(value) {
    is_empty(value)
} else {
    value.ir_type == "FunctionCall"
    arg := value.args[_]
    is_empty(arg)
} else {
    value.ir_type == "FunctionCall"
    arg := value.args[_]
    arg.ir_type == "VariableReference"
    is_credential_field(arg.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_credential_field(var.name)
    check_empty_credential_value(var.value)
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password or secret found in configuration variable - Credentials should not be empty or null. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_credential_field(attr.name)
    check_empty_credential_value(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password or secret found in configuration - Credentials should not be empty or null. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_credential_field(attr.name)
    check_empty_credential_value(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password or secret found in configuration - Credentials should not be empty or null. (CWE-258)"
    }
}