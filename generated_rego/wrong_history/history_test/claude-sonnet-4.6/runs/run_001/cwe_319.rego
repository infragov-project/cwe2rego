package glitch

import data.glitch_lib

cert_disabled(value) {
    value.ir_type == "Boolean"
    value.value == false
}

cert_disabled(value) {
    value.ir_type == "String"
    lower(value.value) == "no"
}

cert_disabled(value) {
    value.ir_type == "String"
    lower(value.value) == "false"
}

encryption_disabled(value) {
    value.ir_type == "Boolean"
    value.value == false
}

encryption_disabled(value) {
    value.ir_type == "String"
    lower(value.value) == "disabled"
}

encryption_disabled(value) {
    value.ir_type == "String"
    lower(value.value) == "false"
}

ssl_flag_names := {
    "ssl_enabled", "tls_enabled", "require_ssl", "https_only",
    "secure_transfer_enabled", "force_https", "enforce_https",
    "transit_encryption_enabled", "encryption_in_transit",
    "node_to_node_encryption_enabled"
}

cert_field_names := {"validate_certs", "ssl_verify", "verify_ssl"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    glitch_lib.traverse(attr.value, "(?i)^(http|ftp|telnet)://")
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Cleartext protocol URL in attribute. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    glitch_lib.traverse(var.value, "(?i)^(http|ftp|telnet)://")
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Cleartext protocol URL in variable. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    walk(var.value, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    lower(entry.key.value) == "protocol"
    entry.value.ir_type == "String"
    lower(entry.value.value) == "http"
    result := {
        "type": "sec_https",
        "element": hash_node,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Cleartext HTTP protocol in configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == cert_field_names[_]
    cert_disabled(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Certificate validation disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == ssl_flag_names[_]
    encryption_disabled(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - SSL/TLS enforcement disabled. (CWE-319)"
    }
}