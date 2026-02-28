package glitch

import data.glitch_lib

# Key attributes indicating missing integrity checks or insecure configurations
protocol_attr_set := {"protocol", "encryption", "ssl", "tls", "secure_channel"}
integrity_attr_set := {"checksum", "integrity_check", "hash", "validation", "verify_checksum", "hmac", "signature"}
unsecured_attr_set := {"insecure", "plaintext"}
secure_attr_set := {"secure"}

# Values indicating insecure or disabled states
insecure_protocol_set := {"http", "ftp", "smtp", "tcp", "udp"}
disabled_set := {"disabled", "none", "false", "no"}
true_set := {"true", "yes", "enabled"}

# Helper to check if a value is false or equivalent
is_false_value(expr) {
    expr.ir_type == "Boolean"
    expr.value == false
} else {
    expr.ir_type == "String"
    lower_value := lower(expr.value)
    disabled_set[lower_value]
} else {
    expr.ir_type == "VariableReference"
    lower_value := lower(expr.value)
    disabled_set[lower_value]
}

# Helper to check if a value is true or equivalent
is_true_value(expr) {
    expr.ir_type == "Boolean"
    expr.value == true
} else {
    expr.ir_type == "String"
    lower_value := lower(expr.value)
    true_set[lower_value]
} else {
    expr.ir_type == "VariableReference"
    lower_value := lower(expr.value)
    true_set[lower_value]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    lower_attr_name := lower(attr.name)
    protocol_attr_set[lower_attr_name]
    attr.value.ir_type == "String"
    lower_value := lower(attr.value.value)
    insecure_protocol_set[lower_value]
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure Protocol Configuration - The configuration uses a protocol without integrity protection (CWE-353)."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    lower_attr_name := lower(attr.name)
    integrity_attr_set[lower_attr_name]
    is_false_value(attr.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Integrity Check - The configuration lacks integrity verification mechanisms (CWE-353)."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    lower_attr_name := lower(attr.name)
    unsecured_attr_set[lower_attr_name]
    is_true_value(attr.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Unsecured Data Transmission - The configuration enables unsecured data transmission (CWE-353)."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    lower_attr_name := lower(attr.name)
    secure_attr_set[lower_attr_name]
    is_false_value(attr.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure Default - The configuration uses insecure defaults (CWE-353)."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "remote_file"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "source"
    attr.value.ir_type == "String"
    lower_value := lower(attr.value.value)
    startswith(lower_value, "http://")
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure Protocol Configuration - The configuration uses a protocol without integrity protection (CWE-353)."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "remote_file"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "source"
    attr.value.ir_type == "Sum"
    attr.value.left.ir_type == "String"
    lower_value := lower(attr.value.left.value)
    startswith(lower_value, "http://")
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure Protocol Configuration - The configuration uses a protocol without integrity protection (CWE-353)."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "remote_file"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "source"
    attr.value.ir_type == "Sum"
    attr.value.right.ir_type == "String"
    lower_value := lower(attr.value.right.value)
    startswith(lower_value, "http://")
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure Protocol Configuration - The configuration uses a protocol without integrity protection (CWE-353)."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "remote_file"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "source"
    attr.value.ir_type == "Sum"
    attr.value.left.ir_type == "Sum"
    attr.value.left.left.ir_type == "String"
    lower_value := lower(attr.value.left.left.value)
    startswith(lower_value, "http://")
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure Protocol Configuration - The configuration uses a protocol without integrity protection (CWE-353)."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "remote_file"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "source"
    attr.value.ir_type == "Sum"
    attr.value.left.ir_type == "Sum"
    attr.value.left.right.ir_type == "String"
    lower_value := lower(attr.value.left.right.value)
    startswith(lower_value, "http://")
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure Protocol Configuration - The configuration uses a protocol without integrity protection (CWE-353)."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "remote_file"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "source"
    attr.value.ir_type == "Sum"
    attr.value.right.ir_type == "Sum"
    attr.value.right.left.ir_type == "String"
    lower_value := lower(attr.value.right.left.value)
    startswith(lower_value, "http://")
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure Protocol Configuration - The configuration uses a protocol without integrity protection (CWE-353)."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "remote_file"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "source"
    attr.value.ir_type == "Sum"
    attr.value.right.ir_type == "Sum"
    attr.value.right.right.ir_type == "String"
    lower_value := lower(attr.value.right.right.value)
    startswith(lower_value, "http://")
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure Protocol Configuration - The configuration uses a protocol without integrity protection (CWE-353)."
    }
}