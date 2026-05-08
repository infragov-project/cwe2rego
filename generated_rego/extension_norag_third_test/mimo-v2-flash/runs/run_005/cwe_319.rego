package glitch

import data.glitch_lib

insecure_protocol_pattern := `(?i)^(http|ftp|telnet|smtp)(://|$)`
credentials_pattern := `(?i)://[^:/@]+:[^/@]+@`

security_attributes := {
    "protocol", "url", "endpoint", "uri", "address", "host", "base_url", "root_url",
    "enable_https_traffic_only", "require_ssl", "use_tls", "ssl_enforcement", 
    "encryption", "ssl_mode", "tls_version", "ssl", "tls", "https_only",
    "ssl_skip_verify", "validate_certs", "ssl_verify", "verify_ssl",
    "public_access_enabled", "public_read_access", "publicly_accessible", "public_access"
}

disabled_values := {"false", "disabled", "no", "off", "0"}

is_disabled(value) {
    value.ir_type == "Boolean"
    value.value == false
} else {
    value.ir_type == "String"
    disabled_values[lower(value.value)]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "String"
    regex.match(insecure_protocol_pattern, n.value)
    
    result := {
        "type": "sec_https",
        "element": n,
        "path": parent.path,
        "description": "Cleartext transmission protocol - Using insecure protocols for data transmission. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "String"
    regex.match(credentials_pattern, n.value)
    
    result := {
        "type": "sec_https",
        "element": n,
        "path": parent.path,
        "description": "Cleartext credentials in URI - Credentials exposed in non-encrypted URI. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    security_attributes[attr.name]
    is_disabled(attr.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Encryption flag disabled - Disabling encryption for data transmission. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    security_attributes[var.name]
    is_disabled(var.value)
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Encryption flag disabled - Disabling encryption for data transmission. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "Hash"
    entry := n.value[_]
    entry.key.ir_type == "String"
    security_attributes[entry.key.value]
    is_disabled(entry.value)
    
    result := {
        "type": "sec_https",
        "element": entry.value,
        "path": parent.path,
        "description": "Encryption flag disabled - Disabling encryption for data transmission. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    vars[_].value.ir_type == "Hash"
    var := vars[_]
    entry := var.value.value[_]
    entry.key.ir_type == "String"
    security_attributes[entry.key.value]
    is_disabled(entry.value)
    
    result := {
        "type": "sec_https",
        "element": entry.value,
        "path": parent.path,
        "description": "Encryption flag disabled - Disabling encryption for data transmission. (CWE-319)"
    }
}