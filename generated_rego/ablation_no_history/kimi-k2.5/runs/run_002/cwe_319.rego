package glitch

import data.glitch_lib

protocol_url_pattern := "^(?i)(http|ftp|telnet|smtp|ldap)://"

string_contains_unencrypted_url(val) {
    val.ir_type == "String"
    regex.match(protocol_url_pattern, val.value)
}

string_contains_unencrypted_url(val) {
    val.ir_type == "String"
    lower(val.value) == "http"
}

string_contains_unencrypted_url(val) {
    val.ir_type == "MethodCall"
    val.receiver.ir_type == "String"
    regex.match(protocol_url_pattern, val.receiver.value)
}

traverse_sum_for_protocol(val) {
    val.ir_type == "Sum"
    traverse_sum_for_protocol(val.left)
}

traverse_sum_for_protocol(val) {
    val.ir_type == "Sum"
    traverse_sum_for_protocol(val.right)
}

traverse_sum_for_protocol(val) {
    val.ir_type == "Sum"
    val.left.ir_type == "String"
    regex.match(protocol_url_pattern, val.left.value)
}

traverse_sum_for_protocol(val) {
    val.ir_type == "Sum"
    val.right.ir_type == "String"
    regex.match(protocol_url_pattern, val.right.value)
}

is_unencrypted_value(val) {
    string_contains_unencrypted_url(val)
}

is_unencrypted_value(val) {
    traverse_sum_for_protocol(val)
}

is_unencrypted_value(val) {
    val.ir_type == "Hash"
    some v
    v := val.value[_]
    string_contains_unencrypted_url(v.value)
}

is_unencrypted_value(val) {
    val.ir_type == "Hash"
    some v
    v := val.value[_]
    traverse_sum_for_protocol(v.value)
}

is_protocol_field(name) {
    lower(name) == "protocol"
}

is_url_field(name) {
    url_fields := {"url", "source", "endpoint", "uri", "dest", "destination", "src", "src_url", "download_url", "repo_url", "baseurl", "mirrorlist"}
    url_fields[lower(name)]
}

is_tls_disabled_name(name) {
    contains(lower(name), "disable_tls")
}

is_tls_disabled_name(name) {
    contains(lower(name), "disable_ssl")
}

is_tls_disabled_name(name) {
    contains(lower(name), "no_encryption")
}

is_tls_disabled_name(name) {
    contains(lower(name), "allow_plaintext")
}

is_tls_disabled_name(name) {
    contains(lower(name), "allow_insecure")
}

is_tls_disabled_name(name) {
    lower(name) == "insecure"
}

is_tls_disabled_name(name) {
    lower(name) == "plain"
}

is_tls_disabled_name(name) {
    contains(lower(name), "unencrypted")
}

is_tls_disabled_name(name) {
    contains(lower(name), "cleartext")
}

is_false_value(val) {
    val.ir_type == "Boolean"
    val.value == false
}

is_false_value(val) {
    val.ir_type == "String"
    lower(val.value) == "false"
}

is_false_value(val) {
    val.ir_type == "String"
    lower(val.value) == "no"
}

is_false_value(val) {
    val.ir_type == "String"
    lower(val.value) == "off"
}

is_false_value(val) {
    val.ir_type == "String"
    lower(val.value) == "disable"
}

is_false_value(val) {
    val.ir_type == "String"
    lower(val.value) == "disabled"
}

is_false_value(val) {
    val.ir_type == "Integer"
    val.value == 0
}

is_true_value(val) {
    val.ir_type == "Boolean"
    val.value == true
}

is_true_value(val) {
    val.ir_type == "String"
    lower(val.value) == "true"
}

is_true_value(val) {
    val.ir_type == "Integer"
    val.value == 1
}

contains_unencrypted_protocol_in_hash(val) {
    val.ir_type == "Hash"
    some kv
    kv := val.value[_]
    kv.key.ir_type == "String"
    is_protocol_field(kv.key.value)
    kv.value.ir_type == "String"
    lower(kv.value.value) == "http"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_protocol_field(attr.name)
    is_unencrypted_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Unencrypted protocol detected where encrypted communication should be used. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_url_field(attr.name)
    is_unencrypted_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure URL using HTTP instead of HTTPS. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    contains_unencrypted_protocol_in_hash(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Hash contains unencrypted protocol configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_protocol_field(var.name)
    is_unencrypted_value(var.value)
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Variable contains unencrypted protocol configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_url_field(var.name)
    is_unencrypted_value(var.value)
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Variable contains insecure URL using HTTP. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    contains_unencrypted_protocol_in_hash(var.value)
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Variable hash contains unencrypted protocol configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_tls_disabled_name(attr.name)
    is_true_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure communication explicitly enabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_tls_disabled_name(var.name)
    is_true_value(var.value)
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure communication explicitly enabled in variable. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    contains(lower(attr.name), "enable_tls")
    is_false_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - TLS is explicitly disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    contains(lower(attr.name), "use_tls")
    is_false_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - TLS is explicitly disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    contains(lower(attr.name), "require_ssl")
    is_false_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - SSL requirement is explicitly disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    contains(lower(attr.name), "enforce_tls")
    is_false_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - TLS enforcement is explicitly disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    contains(lower(attr.name), "ssl_verify")
    is_false_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - SSL certificate verification is disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    contains(lower(attr.name), "validate_certs")
    is_false_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Certificate validation is disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    contains(lower(attr.name), "insecure_skip_verify")
    is_true_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure TLS verification skip is enabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    contains(lower(attr.name), "allow_self_signed")
    is_true_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Self-signed certificates are allowed without proper validation. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    contains(lower(attr.name), "reject_unauthorized")
    is_false_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Unauthorized connections are not rejected. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    contains(lower(attr.name), "tls_version")
    attr.value.ir_type == "String"
    deprecated_versions := {"1.0", "1.1", "sslv3", "tlsv1", "tlsv1_0", "tlsv1_1"}
    deprecated_versions[lower(attr.value.value)]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Deprecated TLS version in use. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    contains(lower(attr.name), "min_tls_version")
    attr.value.ir_type == "String"
    deprecated_versions := {"1.0", "1.1", "sslv3", "tlsv1", "tlsv1_0", "tlsv1_1"}
    deprecated_versions[lower(attr.value.value)]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Deprecated minimum TLS version in use. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    contains(lower(attr.name), "ssl_protocol")
    attr.value.ir_type == "String"
    deprecated_versions := {"1.0", "1.1", "sslv3", "tlsv1", "tlsv1_0", "tlsv1_1"}
    deprecated_versions[lower(attr.value.value)]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Deprecated SSL protocol in use. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    contains(lower(attr.name), "https_only")
    is_false_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - HTTPS-only mode is disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    contains(lower(attr.name), "secure_transfer")
    is_false_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Secure transfer is disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    contains(lower(attr.name), "https_traffic_only")
    is_false_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - HTTPS traffic only mode is disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    contains(lower(attr.name), "ssl_mode")
    attr.value.ir_type == "String"
    insecure_modes := {"disable", "disabled", "false", "no", "off", "optional", "prefer", "allow"}
    insecure_modes[lower(attr.value.value)]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure SSL mode is enabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    contains(lower(attr.name), "encrypt")
    not contains(lower(attr.name), "encrypted")
    is_false_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Encryption is explicitly disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    contains(lower(attr.name), "inflight_encryption")
    is_false_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - In-flight encryption is disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    contains(lower(attr.name), "encryption_in_transit")
    is_false_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Encryption in transit is disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    contains(lower(attr.name), "insecure_registries")
    attr.value.ir_type == "Array"
    count(attr.value.value) > 0
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure container registries configured without TLS. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    contains(lower(var.name), "insecure_registries")
    var.value.ir_type == "Array"
    count(var.value.value) > 0
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure container registries configured without TLS. (CWE-319)"
    }
}