package glitch

import data.glitch_lib

ssl_security_false_attrs := {
    "ssl_enabled", "enable_https", "verify_ssl", "enforce_https",
    "require_ssl", "encryption_in_transit", "in_transit_encryption",
    "https_only", "require_tls", "validate_certs"
}

insecure_true_attrs := {
    "insecure", "disable_ssl", "tls_skip_verify"
}

is_falsy_value(v) {
    v.ir_type == "Boolean"
    v.value == false
}

is_falsy_value(v) {
    v.ir_type == "String"
    lower(v.value) == "no"
}

is_falsy_value(v) {
    v.ir_type == "String"
    lower(v.value) == "false"
}

is_truthy_value(v) {
    v.ir_type == "Boolean"
    v.value == true
}

is_truthy_value(v) {
    v.ir_type == "String"
    lower(v.value) == "yes"
}

is_truthy_value(v) {
    v.ir_type == "String"
    lower(v.value) == "true"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    glitch_lib.traverse(attr.value, "(?i).*http://.*")
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Unencrypted data in transit - Use of plaintext HTTP protocol detected. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    glitch_lib.traverse(v.value, "(?i).*http://.*")
    result := {
        "type": "sec_https",
        "element": v,
        "path": parent.path,
        "description": "Unencrypted data in transit - Use of plaintext HTTP protocol detected. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == ssl_security_false_attrs[_]
    is_falsy_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Unencrypted data in transit - SSL/TLS explicitly disabled or not enforced. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == insecure_true_attrs[_]
    is_truthy_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Unencrypted data in transit - Insecure connection or TLS certificate verification disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    regex.match("(?i)^protocol$", entry.key.value)
    entry.value.ir_type == "String"
    regex.match("(?i)^http$", entry.value.value)
    result := {
        "type": "sec_https",
        "element": entry.value,
        "path": parent.path,
        "description": "Unencrypted data in transit - Protocol explicitly configured as HTTP. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i).*protocol.*", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)^http$", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Unencrypted data in transit - Protocol explicitly configured as HTTP. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match("(?i).*(TLSv?1[._]?0|TLSv?1[._]?1|SSLv?[23]).*", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Unencrypted data in transit - Weak or deprecated TLS/SSL protocol version in use. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i).*(transit_encryption|ssl_mode|encryption_in_transit).*", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)^(disabled?|none|off|false)$", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Unencrypted data in transit - Data transit encryption disabled. (CWE-319)"
    }
}