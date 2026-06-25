package glitch

import data.glitch_lib

insecure_network_values := {
    "0.0.0.0",
    "0.0.0.0/0",
    "::/0",
    "::",
    "any",
    "all",
    "public",
    "world",
    "everyone",
    "anonymous",
    "unrestricted",
    "anywhere",
}

network_binding_patterns := "bind|address|host|ip|listen|cidr|source|origin|endpoint|ingress|egress|access|public|allow|permit|network"

check_insecure_net_value(val) {
    lower_val := lower(val)
    lower_val == insecure_network_values[_]
} else {
    regex.match("^0\\.0\\.0\\.0(/0)?$", val)
} else {
    val == "*"
} else {
    regex.match("^::/?0?$", val)
}

has_network_pattern_name(name) {
    regex.match(sprintf("(?i)%s", [network_binding_patterns]), name)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "String"
    has_network_pattern_name(var.name)
    check_insecure_net_value(var.value.value)

    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": sprintf("Insecure network binding in variable '%s' with value '%s' (CWE-284)", [var.name, var.value.value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "String"
    regex.match("^0\\.0\\.0\\.0(/0)?$", var.value.value)

    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": sprintf("Variable '%s' bound to '%s' - listens on all interfaces (CWE-284)", [var.name, var.value.value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "Hash"
    walk(var.value.value, [_, pair])
    pair.value.ir_type == "String"
    has_network_pattern_name(pair.key.value)
    check_insecure_net_value(pair.value.value)

    result := {
        "type": "sec_invalid_bind",
        "element": pair,
        "path": parent.path,
        "description": sprintf("Insecure network binding in variable '%s' for key '%s' with value '%s' (CWE-284)", [var.name, pair.key.value, pair.value.value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "Hash"
    walk(var.value.value, [_, pair])
    pair.value.ir_type == "String"
    regex.match("^0\\.0\\.0\\.0(/0)?$", pair.value.value)

    result := {
        "type": "sec_invalid_bind",
        "element": pair,
        "path": parent.path,
        "description": sprintf("In variable '%s', key '%s' bound to '%s' - listens on all interfaces (CWE-284)", [var.name, pair.key.value, pair.value.value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "String"
    has_network_pattern_name(attr.name)
    check_insecure_net_value(attr.value.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Insecure network binding in attribute '%s' with value '%s' (CWE-284)", [attr.name, attr.value.value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[attr_name]
    attr.value.ir_type == "String"
    regex.match("^0\\.0\\.0\\.0(/0)?$", attr.value.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Attribute '%s' bound to '%s' - listens on all interfaces (CWE-284)", [attr_name, attr.value.value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[attr_name]
    attr.value.ir_type == "Hash"
    walk(attr.value.value, [_, pair])
    pair.value.ir_type == "String"
    has_network_pattern_name(pair.key.value)
    check_insecure_net_value(pair.value.value)

    result := {
        "type": "sec_invalid_bind",
        "element": pair,
        "path": parent.path,
        "description": sprintf("Insecure network binding in attribute '%s' for key '%s' with value '%s' (CWE-284)", [attr_name, pair.key.value, pair.value.value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[attr_name]
    attr.value.ir_type == "Hash"
    walk(attr.value.value, [_, pair])
    pair.value.ir_type == "String"
    regex.match("^0\\.0\\.0\\.0(/0)?$", pair.value.value)

    result := {
        "type": "sec_invalid_bind",
        "element": pair,
        "path": parent.path,
        "description": sprintf("In attribute '%s', key '%s' bound to '%s' - listens on all interfaces (CWE-284)", [attr_name, pair.key.value, pair.value.value])
    }
}