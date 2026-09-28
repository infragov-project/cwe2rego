package glitch

import data.glitch_lib

http_url_pattern := "(?i)^http://"
ssl_tls_names := {"ssl", "tls", "ssl_enabled", "tls_enabled", "enable_ssl", "enable_tls", "use_ssl", "use_tls"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    glitch_lib.traverse(attr.value, http_url_pattern)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Use of HTTP without SSL/TLS - Communication should use HTTPS instead of HTTP to ensure encrypted and secure communication. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    glitch_lib.traverse(v.value, http_url_pattern)

    result := {
        "type": "sec_https",
        "element": v,
        "path": parent.path,
        "description": "Use of HTTP without SSL/TLS - Communication should use HTTPS instead of HTTP to ensure encrypted and secure communication. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == ssl_tls_names[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Use of HTTP without SSL/TLS - SSL/TLS is explicitly disabled. Communication should be encrypted. (CWE-319)"
    }
}