package glitch

import data.glitch_lib

starts_with_http(value) {
    walk(value, [_, node])
    node.ir_type == "String"
    startswith(node.value, "http://")
}

falsy_string(s) {
    lower(s) == "no"
}

falsy_string(s) {
    lower(s) == "false"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    starts_with_http(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Use of HTTP without SSL/TLS - Attribute uses unencrypted HTTP instead of HTTPS. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    starts_with_http(v.value)
    result := {
        "type": "sec_https",
        "element": v,
        "path": parent.path,
        "description": "Use of HTTP without SSL/TLS - Variable references unencrypted HTTP endpoint. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == "protocol"
    attr.value.ir_type == "String"
    upper(attr.value.value) == "HTTP"
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Use of HTTP without SSL/TLS - Protocol attribute is set to HTTP instead of HTTPS. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    lower(entry.key.value) == "protocol"
    entry.value.ir_type == "String"
    upper(entry.value.value) == "HTTP"
    result := {
        "type": "sec_https",
        "element": entry.value,
        "path": parent.path,
        "description": "Use of HTTP without SSL/TLS - Protocol is set to HTTP in nested Hash configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    starts_with_http(entry.value)
    result := {
        "type": "sec_https",
        "element": entry.value,
        "path": parent.path,
        "description": "Use of HTTP without SSL/TLS - Hash entry uses unencrypted HTTP URL. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    ssl_disabled_flags := {"ssl_enabled", "tls_enabled", "enable_https", "https_only", "require_ssl", "force_https", "redirect_http_to_https"}
    glitch_lib.contains(attr.name, ssl_disabled_flags[_])
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Use of HTTP without SSL/TLS - SSL/TLS feature is explicitly disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    cert_flags := {"validate_certs", "ssl_verify", "verify_ssl", "tls_verify", "verify_peer"}
    glitch_lib.contains(attr.name, cert_flags[_])
    attr.value.ir_type == "String"
    falsy_string(attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Use of HTTP without SSL/TLS - Certificate validation is disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    insecure_flags := {"insecure", "skip_ssl_verify", "ssl_skip_verify", "tls_insecure_skip_verify"}
    glitch_lib.contains(attr.name, insecure_flags[_])
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Use of HTTP without SSL/TLS - Insecure connection flag is explicitly enabled. (CWE-319)"
    }
}