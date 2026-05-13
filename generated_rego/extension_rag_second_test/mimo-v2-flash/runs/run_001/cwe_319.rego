package glitch

import data.glitch_lib

# Rule to detect insecure protocols (HTTP, FTP, Telnet) used in URLs or endpoints
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Traverse the node to find strings containing insecure protocol patterns
    glitch_lib.traverse(node, "(?i)\\b(http|ftp|telnet)://")

    result := {
        "type": "sec_https",
        "element": node,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure protocol detected (CWE-319)"
    }
}

# Rule to detect insecure protocol configuration in attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    # Check attribute names related to protocol or scheme
    attr.name in {"protocol", "scheme"}
    attr.value.ir_type == "String"
    regex.match("(?i)^(http|ftp|telnet)", attr.value.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure protocol configuration (CWE-319)"
    }
}

# Rule to detect insecure encryption flags (e.g., enable_https: false)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    # Check for attributes that disable HTTPS/TLS
    attr.name in {"enable_https", "enable_https_traffic_only", "ssl_enabled", "tls_enabled", "validate_certs"}
    attr.value.ir_type in {"Boolean", "String"}
    (attr.value.ir_type == "Boolean" and attr.value.value == false) or
    (attr.value.ir_type == "String" and regex.match("(?i)^(no|false|disable)", attr.value.value))

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Encryption explicitly disabled (CWE-319)"
    }
}

# Rule to detect insecure ports in attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    # Check for insecure ports (80, 21, 23)
    attr.name == "port"
    (attr.value.ir_type == "String" and regex.match("^(80|21|23)$", attr.value.value)) or
    (attr.value.ir_type == "Integer" and attr.value.value in {80, 21, 23})

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure port configured (CWE-319)"
    }
}

# Rule to detect insecure commands (e.g., wget, curl with HTTP)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Traverse the node to find commands like wget or curl using HTTP
    glitch_lib.traverse(node, "(?i)(wget|curl).*http://")

    result := {
        "type": "sec_https",
        "element": node,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure command detected (CWE-319)"
    }
}