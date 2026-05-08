package glitch

import data.glitch_lib

insecure_protocols := {"http", "ftp", "smtp", "telnet"}

insecure_values := {"no", "false", "disabled", "none", "plaintext"}

security_flag_substrings := {"ssl", "tls", "encrypt", "validate", "enforce", "https", "require"}

is_insecure_string(str) {
    str in insecure_protocols
} else {
    regex.match("^(http|ftp|smtp|telnet)://", str)
}

contains_security_flag(name) {
    substring := security_flag_substrings[_]
    contains(name, substring)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    walk(attr.value, [path, n])
    n.ir_type == "String"
    is_insecure_string(n.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Insecure protocol in attribute value (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    walk(var.value, [path, n])
    n.ir_type == "String"
    is_insecure_string(n.value)
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Insecure protocol in variable value (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    contains_security_flag(attr.name)
    (attr.value.ir_type == "String" and insecure_values[_] == attr.value.value) or
    (attr.value.ir_type == "Boolean" and attr.value.value == false)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Security flag disabled in attribute (CWE-319)"
    }
}