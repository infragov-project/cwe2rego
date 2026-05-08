package glitch

import data.glitch_lib

# Detect insecure protocol usage in string values
is_insecure_protocol(val) {
    val.ir_type == "String"
    regex.match("(?i)^(http://|ftp://|telnet://|smtp://)", val.value)
}

# Detect insecure SSL/TLS configurations (disabled, false, or insecure values)
is_insecure_ssl_config(val) {
    val.ir_type == "Boolean"
    val.value == false
} else {
    val.ir_type == "String"
    regex.match("(?i)^(no|none|false|disabled|disable|0)$", trim_space(val.value))
}

# Check for insecure protocol patterns in nested structures
has_insecure_protocol(node) {
    walk(node, [_, n])
    is_insecure_protocol(n)
}

# Check for insecure SSL configurations in nested structures
has_insecure_ssl(node) {
    walk(node, [_, n])
    is_insecure_ssl_config(n)
}

# Rule 1: Detect insecure protocols in Ansible variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    has_insecure_protocol(v.value)

    result := {
        "type": "sec_https",
        "element": v,
        "path": parent.path,
        "description": "Use of unencrypted protocol - Data transmitted over unencrypted channels may be intercepted. (CWE-319)"
    }
}

# Rule 2: Detect insecure protocols in atomic unit attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    has_insecure_protocol(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Use of unencrypted protocol - Data transmitted over unencrypted channels may be intercepted. (CWE-319)"
    }
}

# Rule 3: Detect insecure SSL/TLS configurations in attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    has_insecure_ssl(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "SSL/TLS encryption disabled - Services should enforce encrypted connections to prevent data exposure. (CWE-319)"
    }
}

# Rule 4: Detect insecure SSL/TLS configurations in variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    has_insecure_ssl(v.value)

    result := {
        "type": "sec_https",
        "element": v,
        "path": parent.path,
        "description": "SSL/TLS encryption disabled - Services should enforce encrypted connections to prevent data exposure. (CWE-319)"
    }
}