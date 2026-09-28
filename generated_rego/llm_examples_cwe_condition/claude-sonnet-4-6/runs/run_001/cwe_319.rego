package glitch

import data.glitch_lib

insecure_bool_names := {
    "enable_https_traffic_only", "https_only", "require_secure_transport",
    "tls_enabled", "enforce_https", "redirect_http_to_https",
    "transit_encryption_enabled", "require_ssl", "force_ssl",
    "hsts_enabled", "secure", "strict_mode", "tls", "require_tls",
    "secure_transfer_required", "ssl"
}

insecure_proto_names := {
    "protocol", "listener_protocol", "frontend_protocol",
    "backend_protocol", "target_group_protocol", "scheme"
}

insecure_tls_names := {
    "ssl_enforcement_enabled", "ssl_policy", "ssl_mode", "mtls_mode",
    "tls_mode", "encryption", "starttls", "smtp_tls_security_level",
    "minimum_tls_version"
}

security_variable_names := {
    "require_secure_transport", "tls_enabled", "ssl_enforcement_enabled",
    "require_ssl", "enforce_https", "https_only", "enable_https_traffic_only",
    "transit_encryption_enabled", "force_ssl", "secure_transfer_required",
    "ssl", "tls", "starttls", "smtp_tls_security_level", "minimum_tls_version"
}

is_false_value(v) {
    v.ir_type == "Boolean"
    v.value == false
}

is_false_value(v) {
    v.ir_type == "String"
    lower(v.value) == "false"
}

is_false_value(v) {
    v.ir_type == "VariableReference"
    lower(v.value) == "false"
}

is_insecure_protocol(v) {
    v.ir_type == "String"
    regex.match("(?i)^(http|ftp|smtp|ldap|telnet|ws)$", v.value)
}

is_insecure_tls_string(v) {
    v.ir_type == "String"
    regex.match("(?i)^(disabled|none|disable|permissive|off|tls1_0|tls1_1|tlsv1|tlsv1\\.1)$", v.value)
}

is_insecure_tls_string(v) {
    v.ir_type == "VariableReference"
    regex.match("(?i)^(disabled|none|disable|permissive|off|tls1_0|tls1_1|tlsv1|tlsv1\\.1)$", v.value)
}

normalize_key(k) = n {
    endswith(k, ":")
    n := trim_right(k, ":")
} else = k { true }

all_paths[p] {
    walk(input, [_, ub])
    ub.ir_type == "UnitBlock"
    ub.path != ""
    p := ub.path
}

all_paths[p] {
    input.ir_type == "UnitBlock"
    input.path != ""
    p := input.path
}

Glitch_Analysis[result] {
    path := all_paths[_]
    walk(input, [_, attr])
    attr.ir_type == "Attribute"
    attr.name == insecure_proto_names[_]
    is_insecure_protocol(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure unencrypted protocol in use. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    path := all_paths[_]
    walk(input, [_, attr])
    attr.ir_type == "Attribute"
    attr.name == insecure_bool_names[_]
    is_false_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": path,
        "description": "Cleartext Transmission of Sensitive Information - TLS/HTTPS enforcement is explicitly disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    path := all_paths[_]
    walk(input, [_, attr])
    attr.ir_type == "Attribute"
    attr.name == insecure_tls_names[_]
    is_insecure_tls_string(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": path,
        "description": "Cleartext Transmission of Sensitive Information - SSL/TLS is disabled or set to insecure mode. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    path := all_paths[_]
    walk(input, [_, attr])
    attr.ir_type == "Attribute"
    attr.value.ir_type == "String"
    regex.match("(?i)(sslmode\\s*=\\s*disabl|encrypt\\s*=\\s*false|^http://)", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": path,
        "description": "Cleartext Transmission of Sensitive Information - Attribute uses insecure or unencrypted connection. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    path := all_paths[_]
    walk(input, [_, attr])
    attr.ir_type == "Attribute"
    attr.value.ir_type == "Hash"
    entry := attr.value.value[_]
    entry.key.ir_type == "String"
    name := normalize_key(entry.key.value)
    name == insecure_bool_names[_]
    is_false_value(entry.value)
    result := {
        "type": "sec_https",
        "element": entry.value,
        "path": path,
        "description": "Cleartext Transmission of Sensitive Information - TLS/HTTPS enforcement disabled in hash config. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    path := all_paths[_]
    walk(input, [_, attr])
    attr.ir_type == "Attribute"
    attr.value.ir_type == "Hash"
    entry := attr.value.value[_]
    entry.key.ir_type == "String"
    name := normalize_key(entry.key.value)
    name == insecure_tls_names[_]
    is_insecure_tls_string(entry.value)
    result := {
        "type": "sec_https",
        "element": entry.value,
        "path": path,
        "description": "Cleartext Transmission of Sensitive Information - SSL/TLS disabled or insecure mode in hash config. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    path := all_paths[_]
    walk(input, [_, attr])
    attr.ir_type == "Attribute"
    attr.value.ir_type == "Hash"
    entry := attr.value.value[_]
    entry.key.ir_type == "String"
    name := normalize_key(entry.key.value)
    name == insecure_proto_names[_]
    is_insecure_protocol(entry.value)
    result := {
        "type": "sec_https",
        "element": entry.value,
        "path": path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure protocol in hash config. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    path := all_paths[_]
    walk(input, [_, attr])
    attr.ir_type == "Attribute"
    attr.value.ir_type == "Hash"
    entry := attr.value.value[_]
    entry.value.ir_type == "String"
    regex.match("(?i)(sslmode\\s*=\\s*disabl|encrypt\\s*=\\s*false|^http://)", entry.value.value)
    result := {
        "type": "sec_https",
        "element": entry.value,
        "path": path,
        "description": "Cleartext Transmission of Sensitive Information - Hash entry uses insecure or unencrypted connection. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    path := all_paths[_]
    walk(input, [_, au])
    au.ir_type == "AtomicUnit"
    var_attr := au.attributes[_]
    var_attr.name == "variable"
    var_attr.value.ir_type == "String"
    lower(var_attr.value.value) == security_variable_names[_]
    val_attr := au.attributes[_]
    val_attr.name == "value"
    is_insecure_tls_string(val_attr.value)
    result := {
        "type": "sec_https",
        "element": val_attr,
        "path": path,
        "description": "Cleartext Transmission of Sensitive Information - Security variable set to insecure value. (CWE-319)"
    }
}