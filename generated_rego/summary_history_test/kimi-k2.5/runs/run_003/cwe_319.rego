package glitch

import data.glitch_lib

insecure_protocols := {"http://", "ftp://", "telnet://", "smtp://"}

disabling_strings := {"no", "false", "off", "disabled", "disable", "0", "skip", "ignore"}

cert_validation_attrs := {"validate_cert", "verify_cert", "verify_certificate", "skip_certificate_check", "ssl_verify", "verify_ssl", "tls_verify", "strict_tls", "check_cert", "ssl_verify_mode", "validate_certs", "skip_certificate_validation", "verify_tls", "check_certificate", "cert_check", "cert_validation", "ssl_check", "tls_check"}

encryption_attrs := {"ssl", "tls", "https", "encryption", "secure", "encrypted", "use_ssl", "enforce_ssl", "require_ssl", "ssl_mode", "sslmode", "tls_version", "min_tls_version", "enable_https", "https_only", "secure_transport", "transit_encryption", "at_rest_encryption", "ssl_policy", "require_secure_transfer", "enable_https_traffic", "insecure", "unencrypted", "require_secure_transfer", "enable_https_traffic_only"}

url_attrs := {"url", "uri", "endpoint", "address", "host", "connection", "source", "location", "server", "api", "base", "target", "mirror"}

is_disabled_value(node) {
    node.ir_type == "Boolean"
    node.value == false
}

is_disabled_value(node) {
    node.ir_type == "String"
    val := lower(node.value)
    val == disabling_strings[_]
}

string_contains_insecure_protocol(str) {
    lower_str := lower(str)
    contains(lower_str, insecure_protocols[_])
}

value_contains_insecure_url(node) {
    node.ir_type == "String"
    string_contains_insecure_protocol(node.value)
}

value_contains_insecure_url(node) {
    node.ir_type == "Sum"
    walk(node, [_, child])
    child.ir_type == "String"
    string_contains_insecure_protocol(child.value)
}

attr_name_matches_url_fragment(name) {
    lower_name := lower(name)
    frag := url_attrs[_]
    contains(lower_name, frag)
}

is_cert_attr(name) {
    lower(name) == cert_validation_attrs[_]
}

is_encryption_attr(name) {
    lower(name) == encryption_attrs[_]
}

is_insecure_protocol_value(node) {
    node.ir_type == "String"
    lower(node.value) == "http"
} else {
    node.ir_type == "String"
    lower(node.value) == "ftp"
}

hash_has_protocol_insecure(node) {
    node.ir_type == "Hash"
    some pair in node.value
    pair.key.ir_type == "String"
    lower(pair.key.value) == "protocol"
    is_insecure_protocol_value(pair.value)
}

walk_contains_insecure_protocol(node) {
    [_, found] := walk(node)
    found.ir_type == "String"
    string_contains_insecure_protocol(found.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, elem])
    elem.ir_type == "Attribute"
    is_cert_attr(elem.name)
    is_disabled_value(elem.value)
    result := {
        "type": "sec_https",
        "element": elem,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Certificate validation disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, elem])
    elem.ir_type == "Attribute"
    is_encryption_attr(elem.name)
    is_disabled_value(elem.value)
    result := {
        "type": "sec_https",
        "element": elem,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Encryption setting disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, elem])
    elem.ir_type == "Attribute"
    attr_name_matches_url_fragment(elem.name)
    value_contains_insecure_url(elem.value)
    result := {
        "type": "sec_https",
        "element": elem,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure HTTP protocol used. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, elem])
    elem.ir_type == "Attribute"
    elem.value.ir_type == "Hash"
    hash_has_protocol_insecure(elem.value)
    result := {
        "type": "sec_https",
        "element": elem,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure HTTP protocol configured in attribute hash. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, elem])
    elem.ir_type == "Variable"
    is_cert_attr(elem.name)
    is_disabled_value(elem.value)
    result := {
        "type": "sec_https",
        "element": elem,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Certificate validation disabled in variable. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, elem])
    elem.ir_type == "Variable"
    is_encryption_attr(elem.name)
    is_disabled_value(elem.value)
    result := {
        "type": "sec_https",
        "element": elem,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Encryption disabled in variable. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, elem])
    elem.ir_type == "Variable"
    attr_name_matches_url_fragment(elem.name)
    value_contains_insecure_url(elem.value)
    result := {
        "type": "sec_https",
        "element": elem,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure HTTP protocol in variable. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, elem])
    elem.ir_type == "Variable"
    elem.value.ir_type == "Hash"
    hash_has_protocol_insecure(elem.value)
    result := {
        "type": "sec_https",
        "element": elem,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure HTTP protocol configured in variable hash. (CWE-319)"
    }
}