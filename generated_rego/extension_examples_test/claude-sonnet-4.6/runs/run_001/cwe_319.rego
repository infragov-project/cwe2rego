package glitch

import data.glitch_lib

secure_enabled_names := {
    "enable_https_traffic_only", "https_only", "require_https", "enforce_https",
    "secure_transfer_required", "redirect_http_to_https", "tls_enabled", "ssl_enabled",
    "ssl", "tls", "require_ssl", "transit_encryption_enabled", "in_transit_encryption_enabled",
    "require_tls", "verify_ssl", "ssl_verify", "validate_certs", "cookie_secure",
    "session_cookie_secure", "https_only_cookie", "transit_encryption"
}

insecure_enabled_names := {
    "allow_http", "insecure_transport", "tls_skip_verify", "insecure_skip_verify",
    "skip_verify", "insecure", "accept_insecure_certs"
}

ssl_mode_names := {"ssl_mode", "in_transit_encryption", "encryption_in_transit"}

tls_version_names := {"minimum_tls_version", "tls_version", "ssl_protocol"}

insecure_ssl_mode_values := {"disable", "none", "prefer", "allow", "disabled", "plaintext"}

insecure_tls_versions := {"tls1_0", "tls1_1", "ssl", "sslv3", "sslv2", "1.0", "1.1"}

disabled_string_values := {"no", "false", "disabled", "0"}

enabled_string_values := {"yes", "true", "enabled", "1"}

is_disabled(value) {
    value.ir_type == "Boolean"
    value.value == false
}

is_disabled(value) {
    value.ir_type == "String"
    lower(value.value) == disabled_string_values[_]
}

is_enabled(value) {
    value.ir_type == "Boolean"
    value.value == true
}

is_enabled(value) {
    value.ir_type == "String"
    lower(value.value) == enabled_string_values[_]
}

has_http_url(node) {
    walk(node, [_, n])
    n.ir_type == "String"
    startswith(n.value, "http://")
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == secure_enabled_names[_]
    is_disabled(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Secure transmission explicitly disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == insecure_enabled_names[_]
    is_enabled(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure transport explicitly enabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == ssl_mode_names[_]
    attr.value.ir_type == "String"
    lower(attr.value.value) == insecure_ssl_mode_values[_]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - SSL/TLS mode is insecure. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == tls_version_names[_]
    attr.value.ir_type == "String"
    lower(attr.value.value) == insecure_tls_versions[_]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Weak or deprecated TLS version. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    has_http_url(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - HTTP URL used in attribute value. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    has_http_url(v.value)
    result := {
        "type": "sec_https",
        "element": v,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Variable contains HTTP URL in cleartext. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i).*protocol.*", attr.name)
    attr.value.ir_type == "String"
    lower(attr.value.value) == "http"
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Protocol set to HTTP. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    walk(v.value, [_, entry])
    entry.key.ir_type == "String"
    lower(entry.key.value) == "protocol"
    entry.value.ir_type == "String"
    lower(entry.value.value) == "http"
    result := {
        "type": "sec_https",
        "element": entry.value,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Protocol set to HTTP in hash configuration. (CWE-319)"
    }
}