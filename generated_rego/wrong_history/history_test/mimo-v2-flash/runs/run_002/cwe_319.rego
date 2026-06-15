package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr_names := {"url", "endpoint", "uri", "connection_string", "protocol", "path"}
    attr.name in attr_names

    attr.value.ir_type == "String"
    url := attr.value.value
    regex.match(`^(http://|ftp://|telnet://|ldap://)`, url)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Using unencrypted protocols for sensitive data. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr_names := {"ssl_enabled", "tls_disabled", "enforce_https", "ssl_mode", "require_ssl", "enable_https_traffic_only"}
    attr.name in attr_names

    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Encryption Disabled Flag - TLS/SSL explicitly disabled for services. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name in {"ssl_mode"}
    attr.value.ir_type == "String"
    regex.match(`(?i)disable`, attr.value.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Encryption Disabled via ssl_mode - Database connection using non-TLS mode. (CWE-319)"
    }
}