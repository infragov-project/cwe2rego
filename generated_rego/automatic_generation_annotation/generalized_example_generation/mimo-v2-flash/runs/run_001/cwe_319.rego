package glitch

import data.glitch_lib

insecure_protocols := {"http", "ftp", "telnet"}
protocol_attributes := {"protocol", "type", "mode", "url", "source", "baseurl"}
encryption_flags := {"ssl_enabled", "ssl", "encryption_in_transit", "enforce_https", "use_secure_connection", "enable_https_traffic_only", "https_only", "require_ssl", "secure_transfer_required", "min_tls_version", "force_https"}

get_string_value(expr) = str {
    expr.ir_type == "String"
    str := expr.value
} else {
    expr.ir_type == "VariableReference"
    str := expr.value
}

is_false_value(expr) {
    expr.ir_type == "Boolean"
    expr.value == false
} else {
    expr.ir_type == "String"
    lower(expr.value) == "false"
} else {
    expr.ir_type == "String"
    lower(expr.value) == "disabled"
} else {
    expr.ir_type == "VariableReference"
    lower(expr.value) == "false"
}

check_hash_key_insecure(key_expr) {
    key_str := get_string_value(key_expr)
    lower_key := lower(key_str)
    clean_key := trim_prefix(lower_key, ":")
    protocol_attributes_lower := {lower(a) | a := protocol_attributes[_]}
    protocol_attributes_lower[clean_key]
}

check_hash_value_insecure(key_expr, value_expr) {
    check_hash_key_insecure(key_expr)
    value_str := get_string_value(value_expr)
    lower_value := lower(value_str)
    insecure_protocols_lower := {lower(p) | p := insecure_protocols[_]}
    insecure_protocols_lower[lower_value]
} else {
    key_str := get_string_value(key_expr)
    lower_key := lower(key_str)
    clean_key := trim_prefix(lower_key, ":")
    encryption_flags_lower := {lower(flag) | flag := encryption_flags[_]}
    encryption_flags_lower[clean_key]
    is_false_value(value_expr)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    lower_name := lower(attr.name)
    protocol_attributes_lower := {lower(a) | a := protocol_attributes[_]}
    protocol_attributes_lower[lower_name]
    attr.value.ir_type == "String"
    regex.match("^(http|ftp|telnet)://", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - The resource uses an unencrypted protocol for data transmission. (CWE-319)"
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
    lower_value := lower(attr.value.value)
    insecure_protocols_lower := {lower(p) | p := insecure_protocols[_]}
    insecure_protocols_lower[lower_value]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - The resource uses an unencrypted protocol for data transmission. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    lower_name := lower(attr.name)
    encryption_flags_lower := {lower(flag) | flag := encryption_flags[_]}
    encryption_flags_lower[lower_name]
    is_false_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Encryption is explicitly disabled for data transmission. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "Hash"
    kv := attr.value.value[_]
    check_hash_value_insecure(kv.key, kv.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Configuration contains insecure settings in nested structure. (CWE-319)"
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
    regex.match("(?i).*protocol\\s*=\\s*http", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Configuration file contains insecure protocol settings. (CWE-319)"
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
    regex.match("(?i).*ssl_mode\\s*=\\s*disabled", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Configuration file contains insecure encryption settings. (CWE-319)"
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
    regex.match("(?i).*require_secure_transport\\s*=\\s*off", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Configuration file contains insecure encryption settings. (CWE-319)"
    }
}