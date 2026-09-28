package glitch

import data.glitch_lib

https_disable_pattern := "(?i).*(https_only|enable_https|require_secure|ssl_enabled|tls_enabled|force_https|secure_transfer).*"

cleartext_url_pattern := "(?i).*(http://|ftp://|telnet://).*"

guard_attr_names := {"unless", "onlyif", "only_if", "not_if", "creates", "path"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    regex.match(https_disable_pattern, attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - HTTPS/SSL/TLS enforcement is explicitly disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attr := node.attributes[_]

    not guard_attr_names[attr.name]
    attr.value.ir_type == "String"
    regex.match(cleartext_url_pattern, attr.value.value)

    result := {
        "type": "sec_https",
        "element": attr.value,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Use of cleartext protocol (HTTP/FTP/Telnet) instead of a secure alternative. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attr := node.attributes[_]

    not guard_attr_names[attr.name]
    attr.value.ir_type == "Hash"
    entry := attr.value.value[_]
    entry.value.ir_type == "String"
    regex.match(cleartext_url_pattern, entry.value.value)

    result := {
        "type": "sec_https",
        "element": entry.value,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Use of cleartext protocol (HTTP/FTP/Telnet) in hash value. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]

    regex.match(https_disable_pattern, v.name)
    v.value.ir_type == "Boolean"
    v.value.value == false

    result := {
        "type": "sec_https",
        "element": v,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - HTTPS/SSL/TLS enforcement is explicitly disabled via variable. (CWE-319)"
    }
}