package glitch

import data.glitch_lib

insecure_protocol_names := {"protocol", "listener_protocol", "backend_protocol", "forwarding_protocol"}
insecure_protocols := {"HTTP", "FTP", "TELNET", "SMTP", "LDAP"}

# Rule 1: Insecure Protocol in Attributes (direct string value)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == insecure_protocol_names[_]
    attr.value.ir_type == "String"
    upper(attr.value.value) == insecure_protocols[_]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure protocol used. (CWE-319)"
    }
}

# Rule 2: Insecure Protocol inside Hash entries (e.g. nested config dicts in variables)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    entry.key.value == insecure_protocol_names[_]
    entry.value.ir_type == "String"
    upper(entry.value.value) == insecure_protocols[_]
    result := {
        "type": "sec_https",
        "element": entry.value,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure protocol in hash configuration. (CWE-319)"
    }
}

# Rule 3: Disabled TLS/SSL via Boolean false
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == {"ssl_enabled", "tls_enabled", "https_enabled", "enable_https_traffic_only", "require_secure_transfer", "enforce_https", "ssl_enforcement_enabled", "require_ssl", "transit_encryption_enabled", "encryption_in_transit", "node_to_node_encryption_enabled", "in_transit_encryption_enabled", "redirect_http_to_https", "enableHttpsTrafficOnly"}[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - TLS/SSL enforcement is disabled. (CWE-319)"
    }
}

# Rule 4: Certificate validation disabled (validate_certs: no / false)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == {"validate_certs", "verify_ssl", "verify_certs", "ssl_verify", "tls_verify"}[_]
    attr.value.ir_type == "String"
    lower(attr.value.value) == {"no", "false", "0"}[_]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Certificate validation disabled. (CWE-319)"
    }
}

# Rule 5: Certificate validation disabled via Boolean false
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == {"validate_certs", "verify_ssl", "verify_certs", "ssl_verify", "tls_verify"}[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Certificate validation disabled. (CWE-319)"
    }
}

# Rule 6: insecure = true
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "insecure"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure flag is enabled. (CWE-319)"
    }
}

# Rule 7: Disabled TLS via String values
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == {"ssl_enforcement", "require_secure_transfer", "secure_transfer_required", "transit_encryption_enabled", "encryption_in_transit", "ssl_enabled", "tls_enabled", "ssl_enforcement_enabled"}[_]
    attr.value.ir_type == "String"
    upper(attr.value.value) == {"DISABLED", "FALSE"}[_]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - TLS/SSL enforcement is disabled. (CWE-319)"
    }
}

# Rule 8: Weak TLS Version
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == {"minimum_tls_version", "min_tls_version", "tls_version", "ssl_protocol", "tls_policy"}[_]
    attr.value.ir_type == "String"
    regex.match("(?i)(TLS1_0|TLS1_1|TLS1\\.0|TLS1\\.1|SSLv3|TLSV1$|TLS_1_0|TLS_1_1)", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Weak or deprecated TLS version configured. (CWE-319)"
    }
}

# Rule 9: Insecure URL scheme in attribute values (traverses complex/Sum values)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    walk(attr.value, [_, leaf])
    leaf.ir_type == "String"
    regex.match("(?i)^(http|ftp|telnet|ldap)://", leaf.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure URL scheme used. (CWE-319)"
    }
}

# Rule 10: Insecure URL scheme in variable values (traverses complex/Sum values)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    walk(v.value, [_, leaf])
    leaf.ir_type == "String"
    regex.match("(?i)^(http|ftp|telnet|ldap)://", leaf.value)
    result := {
        "type": "sec_https",
        "element": v,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure URL scheme used in variable. (CWE-319)"
    }
}

# Rule 11: Insecure connection strings
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match("(?i)(sslmode=disable|encrypt=false|ssl=false|use_ssl=false)", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure connection string with SSL disabled. (CWE-319)"
    }
}

# Rule 12: Cleartext Ports
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == {"port", "from_port", "to_port", "container_port", "target_port"}[_]
    attr.value.ir_type == "Integer"
    attr.value.value == {21, 23, 25, 80, 110, 143, 389, 8008, 8080}[_]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Cleartext protocol port used. (CWE-319)"
    }
}