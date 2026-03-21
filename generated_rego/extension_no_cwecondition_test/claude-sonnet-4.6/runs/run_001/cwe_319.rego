package glitch

import data.glitch_lib

cert_validation_names := {"validate_certs", "verify_ssl", "ssl_verify", "tls_verify", "skip_ssl_verification"}

is_falsy(v) {
    v.ir_type == "Boolean"
    v.value == false
}

is_falsy(v) {
    v.ir_type == "String"
    lower(v.value) == "no"
}

is_falsy(v) {
    v.ir_type == "String"
    lower(v.value) == "false"
}

contains_http_url(node) {
    walk(node, [_, n])
    n.ir_type == "String"
    startswith(lower(n.value), "http://")
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == cert_validation_names[_]
    is_falsy(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Certificate/TLS validation is disabled, allowing insecure connections. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    contains_http_url(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - HTTP URL used instead of HTTPS, transmitting data without encryption. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    contains_http_url(v.value)
    result := {
        "type": "sec_https",
        "element": v,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - HTTP URL used instead of HTTPS, transmitting data without encryption. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    entry.key.value == "protocol"
    entry.value.ir_type == "String"
    entry.value.value == "http"
    result := {
        "type": "sec_https",
        "element": entry.value,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Protocol is configured as HTTP instead of HTTPS. (CWE-319)"
    }
}