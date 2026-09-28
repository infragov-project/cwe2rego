package glitch

import data.glitch_lib

tls_ssl_name_pattern := "(?i).*(\\bssl\\b|\\btls\\b|ssl_enforcement_enabled|enable_https_traffic_only|https_only|require_secure_transport|tls_enabled|ssl_enabled|transit_encryption_enabled|in_transit_encryption_enabled|encryption_in_transit|secure_transfer_required|require_ssl|starttls_enabled|use_tls|cookie_secure|secure_cookies|insecure|redirect_to_https|force_ssl|ssl_redirect).*"

protocol_name_pattern := "(?i).*(\\bprotocol\\b|listener_protocol|frontend_protocol|backend_protocol|client_broker|ssl_enforcement|ssl_mode|tls_mode).*"

weak_tls_attr_pattern := "(?i).*(minimum_tls_version|min_tls_version|tls_policy|tls_minimum).*"

insecure_url_pattern := "(?i)^(http|ftp|telnet|smtp|ldap)://"

insecure_proto_value_pattern := "(?i)^(HTTP|FTP|TELNET|LDAP|SMTP|PLAINTEXT|Disabled|DISABLED|NONE|none|off|http|ftp|telnet|ldap|smtp)$"

tls_disabled_pattern := "(?i)^(Disabled|disable|off|false|NONE|none|0)$"

weak_tls_value_pattern := "(?i)^(TLS1_0|TLS1\\.0|TLS1_1|TLS1\\.1|SSLv3|SSLv2|TLS10|TLS11)$"

insecure_connection_pattern := "(?i)(sslmode\\s*=\\s*disable|Encrypt\\s*=\\s*False|ssl\\s*=\\s*off|force_ssl\\s*=\\s*0)"

security_variable_names := "(?i).*(require_secure_transport|ssl_enforcement|force_ssl|tls_required|require_ssl|ssl_enabled|tls_enabled|starttls|use_tls).*"

port_name_pattern := "(?i).*(\\bport\\b|frontend_port|backend_port|listener_port|http_port).*"

insecure_ports := {80, 21, 23, 25, 110, 143, 389, 8080}

insecure_port_strings := {"80", "21", "23", "25", "110", "143", "389", "8080"}

is_disabled_value(v) {
    v.ir_type == "Boolean"
    v.value == false
}

is_disabled_value(v) {
    v.ir_type == "VariableReference"
    regex.match("(?i)^false$", v.value)
}

is_disabled_value(v) {
    v.ir_type == "String"
    regex.match(tls_disabled_pattern, v.value)
}

is_insecure_port(v) {
    v.ir_type == "Integer"
    v.value == insecure_ports[_]
}

is_insecure_port(v) {
    v.ir_type == "String"
    v.value == insecure_port_strings[_]
}

hash_key_name(entry) = name {
    entry.key.ir_type == "String"
    name := trim_suffix(entry.key.value, ":")
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(tls_ssl_name_pattern, attr.name)
    is_disabled_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - A security flag for encrypted transport is explicitly disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    regex.match(tls_ssl_name_pattern, v.name)
    is_disabled_value(v.value)
    result := {
        "type": "sec_https",
        "element": v,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - A security flag for encrypted transport is explicitly disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    walk(attr.value, [_, entry])
    key_name := hash_key_name(entry)
    regex.match(tls_ssl_name_pattern, key_name)
    is_disabled_value(entry.value)
    result := {
        "type": "sec_https",
        "element": entry.value,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - A security flag for encrypted transport is disabled in a hash configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(protocol_name_pattern, attr.name)
    attr.value.ir_type == "String"
    regex.match(insecure_proto_value_pattern, attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - An insecure or plaintext protocol is configured. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    regex.match(protocol_name_pattern, v.name)
    v.value.ir_type == "String"
    regex.match(insecure_proto_value_pattern, v.value.value)
    result := {
        "type": "sec_https",
        "element": v,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - An insecure or plaintext protocol is configured. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    walk(attr.value, [_, entry])
    key_name := hash_key_name(entry)
    regex.match(protocol_name_pattern, key_name)
    entry.value.ir_type == "String"
    regex.match(insecure_proto_value_pattern, entry.value.value)
    result := {
        "type": "sec_https",
        "element": entry.value,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - An insecure protocol is configured in a hash. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(weak_tls_attr_pattern, attr.name)
    attr.value.ir_type == "String"
    regex.match(weak_tls_value_pattern, attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - A weak TLS version is configured. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match(insecure_url_pattern, attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - A cleartext protocol URL is used. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match(insecure_connection_pattern, attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - A connection string contains insecure transport settings. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    v.value.ir_type == "String"
    regex.match(insecure_connection_pattern, v.value.value)
    result := {
        "type": "sec_https",
        "element": v,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - A connection string contains insecure transport settings. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    var_attr := node.attributes[_]
    var_attr.name == "variable"
    var_attr.value.ir_type == "String"
    regex.match(security_variable_names, var_attr.value.value)
    val_attr := node.attributes[_]
    val_attr.name == "value"
    val_attr.value.ir_type == "String"
    regex.match(tls_disabled_pattern, val_attr.value.value)
    result := {
        "type": "sec_https",
        "element": val_attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - A security variable is set to a disabled value. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(port_name_pattern, attr.name)
    is_insecure_port(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - An insecure port associated with cleartext protocols is configured. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    regex.match(port_name_pattern, v.name)
    is_insecure_port(v.value)
    result := {
        "type": "sec_https",
        "element": v,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - An insecure port associated with cleartext protocols is configured. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    walk(attr.value, [_, entry])
    key_name := hash_key_name(entry)
    regex.match(port_name_pattern, key_name)
    is_insecure_port(entry.value)
    result := {
        "type": "sec_https",
        "element": entry.value,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - An insecure port is configured in a hash. (CWE-319)"
    }
}