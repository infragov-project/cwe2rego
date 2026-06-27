package glitch

import data.glitch_lib

insecure_protocols := {"http", "ftp", "telnet", "smtp", "pop3", "imap"}

insecure_prefixes := {"http://", "ftp://", "telnet://"}

weak_tls_versions := {"sslv3", "ssl", "tlsv1", "tlsv1.0", "tlsv1.1", "1.0", "1.1"}

negative_security_values := {"no", "false", "off", "disabled", "disable", "none", "unencrypted", "plaintext"}

url_related_names := {"url", "uri", "endpoint", "source", "location", "address", "host", "base_url", "api_url", "server_url", "callback_url", "webhook_url", "download_url", "release_url", "repo_url", "mirror_url"}

protocol_names := {"protocol", "scheme"}

ssl_enforcement_names := {"validate_certs", "verify_ssl", "ssl_verify", "verify_peer", "check_certificate", "ssl_check"}

tls_version_names := {"ssl_version", "tls_version", "min_tls_version", "tls_min_version", "minimum_tls_version"}

security_enforcement_names := {"enforce_https", "require_tls", "force_ssl", "https_only", "use_tls", "secure_transport"}

insecurity_flag_names := {"insecure", "insecure_skip_verify", "allow_insecure", "disable_security"}

has_insecure_url_prefix(node) {
    node.ir_type == "String"
    val := lower(node.value)
    startswith(val, insecure_prefixes[_])
}

is_weak_tls_version(node) {
    node.ir_type == "String"
    lower(node.value) == weak_tls_versions[_]
}

is_negative_security(node) {
    node.ir_type == "Boolean"
    node.value == false
}

is_negative_security(node) {
    node.ir_type == "String"
    lower(node.value) == negative_security_values[_]
}

contains_insecure_protocol_in_walk(node) {
    walk(node, [_, n])
    n.ir_type == "String"
    lower(n.value) == insecure_protocols[_]
}

contains_insecure_url_in_walk(node) {
    walk(node, [_, n])
    n.ir_type == "String"
    startswith(lower(n.value), insecure_prefixes[_])
}

is_url_related_name(name) {
    lower(name) == url_related_names[_]
}

is_protocol_name(name) {
    lower(name) == protocol_names[_]
}

is_ssl_enforcement_name(name) {
    lower(name) == ssl_enforcement_names[_]
}

is_tls_version_name(name) {
    lower(name) == tls_version_names[_]
}

is_security_enforcement_name(name) {
    lower(name) == security_enforcement_names[_]
}

is_insecurity_flag_name(name) {
    lower(name) == insecurity_flag_names[_]
}

check_value_insecure(name, value) {
    is_url_related_name(name)
    has_insecure_url_prefix(value)
}

check_value_insecure(name, value) {
    is_protocol_name(name)
    value.ir_type == "String"
    lower(value.value) == insecure_protocols[_]
}

check_value_insecure(name, value) {
    is_insecurity_flag_name(name)
    is_negative_security(value)
}

check_value_insecure(name, value) {
    is_ssl_enforcement_name(name)
    is_negative_security(value)
}

check_value_insecure(name, value) {
    is_tls_version_name(name)
    is_weak_tls_version(value)
}

check_value_insecure(name, value) {
    is_security_enforcement_name(name)
    is_negative_security(value)
}

check_hash_insecure(hash_node) {
    walk(hash_node, [_, n])
    n.ir_type == "KeyValue"
    n.key.ir_type == "String"
    check_value_insecure(n.key.value, n.value)
}

kv_is_insecure(kv) {
    check_value_insecure(kv.name, kv.value)
}

kv_is_insecure(kv) {
    kv.value.ir_type == "Hash"
    check_hash_insecure(kv.value)
}

kv_is_insecure(kv) {
    is_url_related_name(kv.name)
    kv.value.ir_type != "String"
    kv.value.ir_type != "Boolean"
    contains_insecure_url_in_walk(kv.value)
}

kv_is_insecure(kv) {
    is_protocol_name(kv.name)
    kv.value.ir_type != "String"
    contains_insecure_protocol_in_walk(kv.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    kv_is_insecure(var)
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Data transmission channels must use encryption-in-transit to prevent eavesdropping. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    
    kv_is_insecure(attr)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Data transmission channels must use encryption-in-transit to prevent eavesdropping. (CWE-319)"
    }
}