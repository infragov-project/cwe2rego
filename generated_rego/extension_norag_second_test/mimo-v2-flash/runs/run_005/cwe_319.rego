package glitch

import data.glitch_lib

# Helper to detect insecure protocols in string values
check_insecure_protocol(val) {
    val.ir_type == "String"
    regex.match("^(http://|ftp://|telnet://|ws://)", val.value)
} else {
    # Check for Sum (concatenation) that results in insecure protocol
    val.ir_type == "Sum"
    walk(val, [path, node])
    node.ir_type == "String"
    regex.match("^(http://|ftp://|telnet://|ws://)", node.value)
}

# Helper to detect disabled encryption flags
check_disabled_encryption(attr) {
    attr.ir_type == "Attribute"
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    regex.match("(?i)(disable|ssl|tls|secure|https|encrypt|verify|validate|cert)", attr.name)
} else {
    attr.ir_type == "Attribute"
    attr.value.ir_type == "String"
    regex.match("(?i)^(no|false|disable|disabled|off)$", attr.value.value)
    regex.match("(?i)(disable|ssl|tls|secure|https|encrypt|verify|validate|cert)", attr.name)
}

# Detect insecure protocols in attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    check_insecure_protocol(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Unencrypted protocol in attribute. (CWE-319)"
    }
}

# Detect disabled encryption in attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    check_disabled_encryption(attr)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Encryption explicitly disabled. (CWE-319)"
    }
}

# Detect insecure protocols in variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    check_insecure_protocol(var.value)

    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Unencrypted protocol in variable. (CWE-319)"
    }
}