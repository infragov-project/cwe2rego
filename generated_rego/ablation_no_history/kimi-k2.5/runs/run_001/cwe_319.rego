package glitch

import data.glitch_lib

disallowed_insecure_protocols := {"http://", "ftp://", "telnet://", "smtp://", "ldap://"}

disabled_strings := {"false", "disabled", "no", "off", "0", "none", "optional", "optionalnoclient"}

deprecated_tls_versions := {"1.0", "1.1", "v1.0", "v1.1", "tlsv1.0", "tlsv1.1", "sslv3", "sslv2", "2008", "2012", "tls1.0", "tls1.1"}

url_field_patterns := ["url", "source", "dest", "src", "repo", "endpoint", "address", "registry", "download", "base_url", "server_url", "api_url", "origin", "remote"]

encryption_field_patterns := ["ssl", "tls", "verify", "validate", "cert", "insecure", "encryption", "https", "secure"]

protocol_field_patterns := ["protocol", "scheme"]

tls_version_patterns := ["tls_version", "ssl_version", "min_tls", "min_ssl", "cipher", "security_policy"]

has_insecure_protocol_prefix(str) {
    prefix := disallowed_insecure_protocols[_]
    startswith(lower(str), prefix)
}

find_string_in_node(node) = result {
    node.ir_type == "String"
    result = node
} else = result {
    node.ir_type == "Sum"
    result = find_string_in_node(node.left)
} else = result {
    node.ir_type == "Sum"
    result = find_string_in_node(node.right)
} else = result {
    node.ir_type == "MethodCall"
    result = find_string_in_node(node.receiver)
} else = result {
    node.ir_type == "FunctionCall"
    arg := node.args[_]
    result = find_string_in_node(arg)
} else = result {
    node.ir_type == "Array"
    elem := node.value[_]
    result = find_string_in_node(elem)
} else = result {
    node.ir_type == "Hash"
    entry := node.value[_]
    result = find_string_in_node(entry.key)
} else = result {
    node.ir_type == "Hash"
    entry := node.value[_]
    result = find_string_in_node(entry.value)
}

check_insecure_protocol_in_node(node) {
    found := find_string_in_node(node)
    has_insecure_protocol_prefix(found.value)
}

is_url_like_field(name) {
    pattern := url_field_patterns[_]
    regex.match(sprintf("(?i).*%s.*", [pattern]), name)
}

is_encryption_field(name) {
    pattern := encryption_field_patterns[_]
    regex.match(sprintf("(?i).*%s.*", [pattern]), name)
}

is_protocol_field(name) {
    pattern := protocol_field_patterns[_]
    regex.match(sprintf("(?i).*%s.*", [pattern]), name)
}

is_tls_version_field(name) {
    pattern := tls_version_patterns[_]
    regex.match(sprintf("(?i).*%s.*", [pattern]), name)
}

is_disabled_or_insecure(node) {
    node.ir_type == "Boolean"
    node.value == false
} else {
    node.ir_type == "String"
    lower(node.value) == disabled_strings[_]
} else {
    node.ir_type == "Integer"
    node.value == 0
}

is_http_protocol_value(node) {
    node.ir_type == "String"
    lower(node.value) == "http"
}

has_deprecated_tls(node) {
    node.ir_type == "String"
    ver := deprecated_tls_versions[_]
    regex.match(sprintf("(?i).*%s.*", [ver]), lower(node.value))
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := parent.variables[_]
    check_insecure_protocol_in_node(vars.value)
    result := {
        "type": "sec_https",
        "element": vars,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Unencrypted protocol detected in variable value. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    check_insecure_protocol_in_node(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Unencrypted protocol detected in attribute value. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    is_protocol_field(attr.name)
    is_http_protocol_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure HTTP protocol explicitly configured. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := parent.variables[_]
    vars.value.ir_type == "Hash"
    entry := vars.value.value[_]
    lower(entry.key.value) == "protocol"
    is_http_protocol_value(entry.value)
    result := {
        "type": "sec_https",
        "element": vars,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure HTTP protocol configured in configuration block. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    is_encryption_field(attr.name)
    is_disabled_or_insecure(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Security verification or encryption is disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    is_tls_version_field(attr.name)
    has_deprecated_tls(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Deprecated TLS/SSL version in use. (CWE-319)"
    }
}