package glitch

import data.glitch_lib

# Rule 1: Detect insecure protocol URLs in attribute values (http://, ftp://, telnet://)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match("(?i)^(http|ftp|telnet)://", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure protocol URL detected. Use HTTPS or encrypted alternatives. (CWE-319)"
    }
}

# Rule 2: Security enforcement boolean attributes set to false
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(https_only|enable_https|require_ssl|force_ssl|transit_encryption_enabled|secure_transfer_required|enable_https_traffic_only|require_secure_transfer|in_flight_encryption|enforce_https|require_secure_transport|redirect_http_to_https)", attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Encryption-in-transit is disabled. Ensure encrypted communication is enforced. (CWE-319)"
    }
}

# Rule 3: SSL/TLS/encryption explicitly disabled via string value
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(ssl_enforcement|ssl_mode|transit_encryption_mode|tls_enforcement|encryption_in_transit|transit_encryption|ssl_policy)", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)^(disabled|disable|false|no|none|off)$", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - SSL/TLS or encryption is explicitly disabled. (CWE-319)"
    }
}

# Rule 4: Weak TLS versions configured
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(tls_version|minimum_tls|ssl_protocol)", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)(TLS1\\.0|TLS1\\.1|TLSv1\\.0|TLSv1\\.1|TLS10|TLS11)", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Weak TLS version configured. Use TLS 1.2 or higher. (CWE-319)"
    }
}

# Rule 5: Insecure protocol in protocol-type attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(listener_protocol|frontend_protocol|backend_protocol|endpoint_protocol|origin_protocol_policy)", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)^(HTTP|FTP|TELNET|http-only|http_only)$", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure protocol configured for communication endpoint. (CWE-319)"
    }
}

# Rule 6: Insecure or allow_http flags explicitly set to true
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(^insecure$|allow_http$)", attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure or plaintext communication explicitly enabled. (CWE-319)"
    }
}