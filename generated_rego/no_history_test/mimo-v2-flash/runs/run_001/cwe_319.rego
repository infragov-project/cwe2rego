package glitch

import data.glitch_lib

insecure_protocol_names := {"protocol", "network_protocol", "load_balancer_protocol"}
insecure_protocols := {"http", "ftp", "telnet", "smtp"}

encryption_disable_names := {"enable_https", "https_only", "ssl", "encryption", "force_https", "require_secure_transport", "secure_transfer", "enforce_https", "validate_certs"}
encryption_disable_values := {"disabled", "none", "no"}

insecure_tls_names := {"tls_version", "ssl_version"}
insecure_tls_versions := {"tls_1.0", "tls_1.1", "ssl_2.0", "ssl_3.0"}

insecure_boolean_names := {"disable_encryption", "allow_insecure_connections", "public_network_access"}
insecure_boolean_values := {"enabled"}

insecure_bucket_names := {"bucket_policy", "acl"}
insecure_bucket_patterns := {"allow_http", "public-read", "public-read-write"}

is_insecure_protocol(name, value) {
    name == insecure_protocol_names[_]
    value.ir_type == "String"
    regex.match(sprintf("(?i)^(%s)$", [concat("|", insecure_protocols)]), value.value)
}

is_insecure_encryption_disable(name, value) {
    name == encryption_disable_names[_]
    value.ir_type == "String"
    value.value == encryption_disable_values[_]
}

is_insecure_encryption_boolean(name, value) {
    name == encryption_disable_names[_]
    value.ir_type == "Boolean"
    value.value == false
}

is_insecure_tls(name, value) {
    name == insecure_tls_names[_]
    value.ir_type == "String"
    value.value == insecure_tls_versions[_]
}

is_insecure_boolean_true(name, value) {
    name == insecure_boolean_names[_]
    value.ir_type == "Boolean"
    value.value == true
}

is_insecure_boolean_string(name, value) {
    name == insecure_boolean_names[_]
    value.ir_type == "String"
    value.value == insecure_boolean_values[_]
}

is_insecure_bucket(name, value) {
    name == insecure_bucket_names[_]
    value.ir_type == "String"
    contains(value.value, insecure_bucket_patterns[_])
}

is_insecure_container_port(name, value) {
    name == "container_port"
    value.ir_type == "Integer"
    value.value == 80
}

is_insecure_container_port_string(name, value) {
    name == "container_port"
    value.ir_type == "String"
    value.value == "80"
}

is_insecure_value(value) {
    walk(value, [_, node])
    node.ir_type == "String"
    regex.match("(?i)^(http|ftp|telnet|smtp)://", node.value)
}

check_key_value_pair(name, value) {
    is_insecure_protocol(name, value)
} else {
    is_insecure_encryption_disable(name, value)
} else {
    is_insecure_encryption_boolean(name, value)
} else {
    is_insecure_tls(name, value)
} else {
    is_insecure_boolean_true(name, value)
} else {
    is_insecure_boolean_string(name, value)
} else {
    is_insecure_bucket(name, value)
} else {
    is_insecure_container_port(name, value)
} else {
    is_insecure_container_port_string(name, value)
} else {
    is_insecure_value(value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    check_key_value_pair(attr.name, attr.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - The software transmits sensitive information in cleartext. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    walk(var.value, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    pair.key.ir_type == "String"
    pair.value.ir_type == "String"
    
    check_key_value_pair(pair.key.value, pair.value)
    
    result := {
        "type": "sec_https",
        "element": pair.key,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - The software transmits sensitive information in cleartext. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    is_insecure_value(var.value)
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - The software transmits sensitive information in cleartext. (CWE-319)"
    }
}