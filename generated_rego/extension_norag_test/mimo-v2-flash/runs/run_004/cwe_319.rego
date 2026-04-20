package glitch

import data.glitch_lib

insecure_protocols = {"http://", "ftp://", "smtp://", "telnet://"}
insecure_protocol_values = {"http", "ftp", "smtp", "telnet", "plaintext"}
insecure_ports = {80, 21, 25, 23, 587, 143, 110}
encryption_flag_names = {"https_only", "ssl_enabled", "enable_https", "require_ssl", "enable_https_traffic_only", "enforce_https", "validate_certs", "ssl_mode", "use_ssl", "start_tls", "ssl_skip_verify"}
insecure_encryption_values = {false, "false", "no", "disabled", "none", "disable"}
secret_keywords = {"password", "api_key", "secret", "key", "token", "credential", "secret_key", "api_token", "client_secret", "auth_token"}

# Check for insecure protocols in URLs and strings
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "String"
    regex.match("http://|ftp://|smtp://|telnet://", node.value)
    result := {
        "type": "sec_https",
        "element": node,
        "path": parent.path,
        "description": "Unencrypted protocol found in URL or string. (CWE-319)"
    }
}

# Check for insecure protocol values in attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name in {"protocol", "backend_protocol", "listener_protocol", "url", "endpoint"}
    attr.value.ir_type == "String"
    attr.value.value in insecure_protocol_values
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Insecure protocol configuration. (CWE-319)"
    }
}

# Check for disabled encryption flags
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name in encryption_flag_names
    (
        attr.value.ir_type == "Boolean" and attr.value.value == false
        or
        attr.value.ir_type == "String" and attr.value.value in insecure_encryption_values
    )
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Encryption disabled. (CWE-319)"
    }
}

# Check for insecure port configurations
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name in {"port", "ports", "from_port", "to_port", "ingress_port", "egress_port"}
    (
        attr.value.ir_type == "Integer" and attr.value.value in insecure_ports
        or
        attr.value.ir_type == "String" and to_number(attr.value.value) in insecure_ports
    )
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Insecure port configuration. (CWE-319)"
    }
}

# Check for plaintext secrets in attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "String"
    some keyword in secret_keywords
    regex.match(sprintf("(?i).*%s.*", [keyword]), attr.name)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Plaintext secret in configuration. (CWE-319)"
    }
}

# Check for public access without encryption
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name in {"public_access", "public_network_access", "allow_blob_public_access"}
    (
        attr.value.ir_type == "Boolean" and attr.value.value == true
        or
        attr.value.ir_type == "String" and attr.value.value in {"enabled", "true", "public"}
    )
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Public access enabled without encryption. (CWE-319)"
    }
}

# Check for insecure values in Hash structures (e.g., variables with Hash values)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    pair.key.ir_type == "String"
    pair.key.value in {"protocol", "url", "endpoint", "backend_protocol", "listener_protocol"}
    pair.value.ir_type == "String"
    regex.match("http://|ftp://|smtp://|telnet://", pair.value.value)
    result := {
        "type": "sec_https",
        "element": pair,
        "path": parent.path,
        "description": "Insecure protocol in Hash configuration. (CWE-319)"
    }
}