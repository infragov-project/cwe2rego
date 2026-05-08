package glitch

import data.glitch_lib

insecure_boolean_attributes := {
    "validate_certs", "sslverify", "verify_ssl", "gpgcheck", "check_package_signatures",
    "checksum", "enable_checksum", "integrity_check", "data_integrity", "integrity_verification",
    "encryption", "enable_encryption", "tls", "ssl", "require_tls", "secure", "ssl_enabled",
    "tls_enabled", "secure_channel", "message_integrity", "authentication", "auth", "validate",
    "signature_validation", "hash_verification"
}

insecure_string_attributes := {
    "protocol", "ssl_version", "tls_version", "ssl_mode", "signature_version",
    "data_integrity", "integrity_verification", "security_policy", "fallback_protocol",
    "checksum_algorithm", "digest_algorithm", "hash_algorithm", "url", "source", "baseurl",
    "mirrorlist", "download_url", "endpoint", "uri", "link", "location", "path", "repo",
    "repository", "src", "mode", "permissions"
}

url_attributes := {
    "url", "source", "baseurl", "mirrorlist", "download_url", "endpoint", "uri", "link",
    "location", "path", "repo", "repository", "src"
}

insecure_url_prefixes := {"http://", "ftp://", "telnet://", "smtp://", "tftp://"}

insecure_string_values := {
    "http", "ftp", "telnet", "smtp", "tftp", "tcp", "udp", "2.0", "3.0", "1.0", "1.1",
    "none", "disabled", "false", "no", "off", "0", "0000", "000", "00", "null", "empty",
    "", "cleartext", "plain", "anonymous", "guest", "admin", "root", "password", "secret",
    "apikey", "api_key", "access_key", "secret_key", "client_secret", "client_id", "username",
    "user", "login", "signing_key", "private_key", "public_key", "gpgkey", "0644", "0600", 
    "0777", "0755", "644", "600", "777", "755"
}

is_security_relevant(key) {
    key.ir_type == "String"
    n := lower(key.value)
    insecure_boolean_attributes[n]
} else {
    key.ir_type == "String"
    n := lower(key.value)
    insecure_string_attributes[n]
} else {
    key.ir_type == "String"
    n := lower(key.value)
    url_attributes[n]
}

is_insecure_string_value(value) {
    value.ir_type == "String"
    lower_value := lower(value.value)
    insecure_string_values[lower_value]
}

is_insecure_url_value(value) {
    value.ir_type == "String"
    lower_value := lower(value.value)
    insecure_prefix := insecure_url_prefixes[_]
    startswith(lower_value, insecure_prefix)
}

is_insecure_boolean_value(value) {
    value.ir_type == "Boolean"
    value.value == false
} else {
    value.ir_type == "Integer"
    value.value == 0
}

is_insecure_attr(key, value) {
    is_security_relevant(key)
    key.ir_type == "String"
    lower_key := lower(key.value)
    insecure_boolean_attributes[lower_key]
    is_insecure_boolean_value(value)
} else {
    is_security_relevant(key)
    key.ir_type == "String"
    lower_key := lower(key.value)
    insecure_string_attributes[lower_key]
    is_insecure_string_value(value)
} else {
    is_security_relevant(key)
    key.ir_type == "String"
    lower_key := lower(key.value)
    url_attributes[lower_key]
    is_insecure_url_value(value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    [path, node] := walk(parent)
    node.ir_type == "Attribute"
    key := {"ir_type": "String", "value": node.name}
    value := node.value
    is_insecure_attr(key, value)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing support for integrity check (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    [path, node] := walk(parent)
    node.ir_type == "Variable"
    key := {"ir_type": "String", "value": node.name}
    value := node.value
    is_insecure_attr(key, value)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing support for integrity check (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    [path, node] := walk(parent)
    node.ir_type == "Hash"
    pair := node.value[_]
    key := pair.key
    value := pair.value
    is_insecure_attr(key, value)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing support for integrity check (CWE-353)"
    }
}