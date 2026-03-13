package glitch

import data.glitch_lib

weak_protocols = {"http", "ftp", "smtp"}
weak_ssl_attributes = {"ssl_enabled", "tls_version", "encryption", "secure_connection", "use_https", "https_only", "ssl"}
weak_ssl_values = {"none", "disabled"}
weak_transfer_attributes = {"enable_https_traffic_only", "require_ssl", "ssl_mode", "enforce_https", "db_ssl_mode"}
weak_transfer_values = {"disabled"}
weak_endpoint_attributes = {"endpoint", "uri", "port", "source", "url", "location", "baseurl"}
weak_enforcement_attributes = {"redirect_http_to_https", "encryption_policy"}
weak_enforcement_values = {"optional"}

check_weak_ssl_value(value) {
    value.ir_type == "Boolean"
    value.value == false
} else {
    value.ir_type == "String"
    weak_ssl_values[value.value]
}

check_weak_transfer_value(value) {
    value.ir_type == "Boolean"
    value.value == false
} else {
    value.ir_type == "String"
    weak_transfer_values[value.value]
}

check_weak_enforcement_value(value) {
    value.ir_type == "Boolean"
    value.value == false
} else {
    value.ir_type == "String"
    weak_enforcement_values[value.value]
}

check_weak_endpoint_value(value) {
    value.ir_type == "String"
    regex.match("http://", value.value)
} else {
    value.ir_type == "String"
    regex.match("ftp://", value.value)
} else {
    value.ir_type == "String"
    regex.match("telnet://", value.value)
} else {
    value.ir_type == "Integer"
    value.value == 80
} else {
    value.ir_type == "Integer"
    value.value == 21
} else {
    value.ir_type == "Integer"
    value.value == 23
}

# Check variables for weak protocol
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    variable := variables[_]
    variable.name == "protocol"
    variable.value.ir_type == "String"
    weak_protocols[variable.value.value]
    result := {
        "type": "sec_https",
        "element": variable,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Using unencrypted protocol for data transmission. (CWE-319)"
    }
}

# Check variables for weak SSL configuration
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    variable := variables[_]
    weak_ssl_attributes[variable.name]
    check_weak_ssl_value(variable.value)
    result := {
        "type": "sec_https",
        "element": variable,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Misconfigured SSL/TLS settings. (CWE-319)"
    }
}

# Check variables for weak transfer configuration
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    variable := variables[_]
    weak_transfer_attributes[variable.name]
    check_weak_transfer_value(variable.value)
    result := {
        "type": "sec_https",
        "element": variable,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Misconfigured secure transfer settings. (CWE-319)"
    }
}

# Check variables for weak endpoint configuration
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    variable := variables[_]
    weak_endpoint_attributes[variable.name]
    check_weak_endpoint_value(variable.value)
    result := {
        "type": "sec_https",
        "element": variable,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure endpoint configuration. (CWE-319)"
    }
}

# Check atomic units for weak protocol
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "protocol"
    attr.value.ir_type == "String"
    weak_protocols[attr.value.value]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Using unencrypted protocol for data transmission. (CWE-319)"
    }
}

# Check atomic units for weak SSL configuration
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    weak_ssl_attributes[attr.name]
    check_weak_ssl_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Misconfigured SSL/TLS settings. (CWE-319)"
    }
}

# Check atomic units for weak transfer configuration
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    weak_transfer_attributes[attr.name]
    check_weak_transfer_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Misconfigured secure transfer settings. (CWE-319)"
    }
}

# Check atomic units for weak endpoint configuration
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    weak_endpoint_attributes[attr.name]
    check_weak_endpoint_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure endpoint configuration. (CWE-319)"
    }
}

# Check atomic units for weak enforcement configuration
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    weak_enforcement_attributes[attr.name]
    check_weak_enforcement_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Missing enforcement of encryption controls. (CWE-319)"
    }
}