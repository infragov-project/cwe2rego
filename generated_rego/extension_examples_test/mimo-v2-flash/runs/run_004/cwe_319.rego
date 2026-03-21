package glitch

import data.glitch_lib

protocol_names := {"protocol", "scheme"}
protocol_values := {"http", "ftp", "smtp", "telnet", "ldap", "tcp"}
encryption_flag_names := {"enable_https", "require_ssl", "use_ssl", "ssl_enabled", "https_only", "force_ssl", "disable_https", "enable_https_traffic_only", "validate_certs", "ssl_mode", "start_tls"}
disabled_values := {"no", "false", "disable", "disabled"}
url_names := {"url", "endpoint", "uri", "location", "source"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    protocol_names[attr.name]
    attr.value.ir_type == "String"
    regex.match("(?i)^(http|ftp|smtp|telnet|ldap|tcp)$", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission protocol detected - Using unencrypted protocol. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    encryption_flag_names[attr.name]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission encryption flag disabled - Encryption is not enabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    encryption_flag_names[attr.name]
    attr.value.ir_type == "String"
    regex.match("(?i)^(no|false|disable|disabled)$", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission encryption flag disabled - Encryption is not enabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    url_names[attr.name]
    attr.value.ir_type == "String"
    regex.match("(?i)^http://", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission URL detected - URL using HTTP protocol. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    url_names[attr.name]
    attr.value.ir_type == "Sum"
    walk(attr.value, [_, n])
    n.ir_type == "String"
    regex.match("(?i)^http://", n.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission URL detected - URL using HTTP protocol. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    var.value.ir_type == "Hash"
    hash_pair := var.value.value[_]
    key := hash_pair.key
    value := hash_pair.value
    key.ir_type == "String"
    protocol_names[key.value]
    value.ir_type == "String"
    regex.match("(?i)^(http|ftp|smtp|telnet|ldap|tcp)$", value.value)
    result := {
        "type": "sec_https",
        "element": value,
        "path": parent.path,
        "description": "Cleartext transmission protocol detected in variable - Using unencrypted protocol. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    var.value.ir_type == "Hash"
    hash_pair := var.value.value[_]
    key := hash_pair.key
    value := hash_pair.value
    key.ir_type == "String"
    encryption_flag_names[key.value]
    value.ir_type == "Boolean"
    value.value == false
    result := {
        "type": "sec_https",
        "element": value,
        "path": parent.path,
        "description": "Cleartext transmission encryption flag disabled in variable - Encryption is not enabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    var.value.ir_type == "Hash"
    hash_pair := var.value.value[_]
    key := hash_pair.key
    value := hash_pair.value
    key.ir_type == "String"
    encryption_flag_names[key.value]
    value.ir_type == "String"
    regex.match("(?i)^(no|false|disable|disabled)$", value.value)
    result := {
        "type": "sec_https",
        "element": value,
        "path": parent.path,
        "description": "Cleartext transmission encryption flag disabled in variable - Encryption is not enabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    var.value.ir_type == "Hash"
    hash_pair := var.value.value[_]
    key := hash_pair.key
    value := hash_pair.value
    key.ir_type == "String"
    url_names[key.value]
    value.ir_type == "String"
    regex.match("(?i)^http://", value.value)
    result := {
        "type": "sec_https",
        "element": value,
        "path": parent.path,
        "description": "Cleartext transmission URL detected in variable - URL using HTTP protocol. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    var.value.ir_type == "Hash"
    hash_pair := var.value.value[_]
    key := hash_pair.key
    value := hash_pair.value
    key.ir_type == "String"
    url_names[key.value]
    value.ir_type == "Sum"
    walk(value, [_, n])
    n.ir_type == "String"
    regex.match("(?i)^http://", n.value)
    result := {
        "type": "sec_https",
        "element": value,
        "path": parent.path,
        "description": "Cleartext transmission URL detected in variable - URL using HTTP protocol. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    var.value.ir_type == "String"
    regex.match("(?i)^http://", var.value.value)
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission URL detected in variable - URL using HTTP protocol. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    var.value.ir_type == "Sum"
    walk(var.value, [_, n])
    n.ir_type == "String"
    regex.match("(?i)^http://", n.value)
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission URL detected in variable - URL using HTTP protocol. (CWE-319)"
    }
}