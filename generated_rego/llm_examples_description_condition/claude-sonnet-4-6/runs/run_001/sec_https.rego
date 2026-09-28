package glitch

import data.glitch_lib

normalize_key(k) = r {
    endswith(k, ":")
    r := substring(k, 0, count(k) - 1)
} else = k

get_key_str(entry) = k {
    entry.key.ir_type == "String"
    k := normalize_key(entry.key.value)
}

get_key_str(entry) = k {
    entry.key.ir_type == "VariableReference"
    k := normalize_key(entry.key.value)
}

http_ports := {80, 8080}

is_http_url(v) {
    v.ir_type == "String"
    regex.match("(?i)http://", v.value)
}

is_http_protocol_value(v) {
    v.ir_type == "String"
    upper(v.value) == "HTTP"
}

is_http_endpoint_value(v) {
    v.ir_type == "String"
    regex.match("(?i)^http:[0-9]+", v.value)
    not regex.match("(?i)^https:", v.value)
}

is_http_port_val(v) {
    v.ir_type == "Integer"
    v.value == http_ports[_]
}

is_bool_false(v) {
    v.ir_type == "Boolean"
    v.value == false
}

is_bool_false(v) {
    v.ir_type == "VariableReference"
    lower(v.value) == "false"
}

is_bool_true(v) {
    v.ir_type == "Boolean"
    v.value == true
}

is_bool_true(v) {
    v.ir_type == "VariableReference"
    lower(v.value) == "true"
}

is_null_or_undef(v) {
    v.ir_type == "Null"
}

is_null_or_undef(v) {
    v.ir_type == "Undef"
}

key_is_protocol(k) {
    regex.match("(?i)protocol", k)
}

key_is_port(k) {
    regex.match("(?i)(^|_)port$", k)
}

key_is_ssl_toggle(k) {
    regex.match("(?i)^(ssl|ssl_enabled|enable_https|require_ssl|validate_certs|redirect_http_to_https|rewrite_to_https|force_https|insecure_skip_verify)$", k)
}

key_is_ssl_cert(k) {
    regex.match("(?i)(ssl_cert|ssl_key|ssl_certificate|certificate_arn|ssl_certificate_id)", k)
}

key_is_ssl_policy(k) {
    regex.match("(?i)^ssl_policy$", k)
}

key_is_insecure(k) {
    regex.match("(?i)^insecure$", k)
}

is_multiline_string(v) {
    v.ir_type == "String"
    contains(v.value, "\n")
}

is_protocol_indicator_string(s) {
    regex.match("(?i)protocol[=:][\\s\"']*http", s)
    not regex.match("(?i)protocol[=:][\\s\"']*https", s)
}

kv_is_vulnerable(a) {
    is_http_url(a.value)
    not is_multiline_string(a.value)
}

kv_is_vulnerable(a) {
    key_is_protocol(normalize_key(a.name))
    is_http_protocol_value(a.value)
}

kv_is_vulnerable(a) {
    key_is_port(normalize_key(a.name))
    is_http_port_val(a.value)
}

kv_is_vulnerable(a) {
    key_is_ssl_toggle(normalize_key(a.name))
    is_bool_false(a.value)
}

kv_is_vulnerable(a) {
    key_is_insecure(normalize_key(a.name))
    is_bool_true(a.value)
}

kv_is_vulnerable(a) {
    key_is_ssl_cert(normalize_key(a.name))
    is_null_or_undef(a.value)
}

kv_is_vulnerable(a) {
    key_is_ssl_policy(normalize_key(a.name))
    is_null_or_undef(a.value)
}

kv_is_vulnerable(a) {
    key_is_ssl_policy(normalize_key(a.name))
    a.value.ir_type == "String"
    lower(a.value.value) == "none"
}

kv_is_vulnerable(a) {
    is_http_endpoint_value(a.value)
}

hash_entry_vulnerable(key_str, val) {
    is_http_url(val)
}

hash_entry_vulnerable(key_str, val) {
    key_is_protocol(key_str)
    is_http_protocol_value(val)
}

hash_entry_vulnerable(key_str, val) {
    key_is_port(key_str)
    is_http_port_val(val)
}

hash_entry_vulnerable(key_str, val) {
    key_is_ssl_toggle(key_str)
    is_bool_false(val)
}

hash_entry_vulnerable(key_str, val) {
    key_is_insecure(key_str)
    is_bool_true(val)
}

hash_entry_vulnerable(key_str, val) {
    key_is_ssl_cert(key_str)
    is_null_or_undef(val)
}

hash_entry_vulnerable(key_str, val) {
    key_is_ssl_policy(key_str)
    is_null_or_undef(val)
}

hash_entry_vulnerable(key_str, val) {
    key_is_ssl_policy(key_str)
    val.ir_type == "String"
    lower(val.value) == "none"
}

hash_entry_vulnerable(key_str, val) {
    is_http_endpoint_value(val)
}

multiline_line_vulnerable(line) {
    regex.match("(?i)http://", line)
}

multiline_line_vulnerable(line) {
    regex.match("(?i)(protocol|scheme)\\s*[=:>\"'\\s]+HTTP([^Ss]|$)", line)
}

multiline_line_vulnerable(line) {
    regex.match("(?i)(ssl_enabled|enable_https|require_ssl|redirect_http_to_https|rewrite_to_https|force_https)\\s*[=:>]\\s*false", line)
}

multiline_line_vulnerable(line) {
    regex.match("(?i)insecure\\s*[=:>]\\s*true", line)
}

multiline_line_vulnerable(line) {
    regex.match("(?i)(ssl_cert|ssl_key|ssl_certificate|certificate_arn|ssl_certificate_id|ssl_policy)\\s*[=:>]\\s*(undef|null|~|\"\")", line)
}

array_string_vulnerable(s) {
    is_protocol_indicator_string(s)
}

array_string_vulnerable(s) {
    regex.match("(?i)http://", s)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    au := glitch_lib.all_atomic_units(parent)[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    kv_is_vulnerable(attr)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Use of HTTP without SSL/TLS - Insecure HTTP configuration detected. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    au := glitch_lib.all_atomic_units(parent)[_]
    attr := au.attributes[_]
    walk(attr.value, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    key_str := get_key_str(entry)
    hash_entry_vulnerable(key_str, entry.value)
    result := {
        "type": "sec_https",
        "element": entry.key,
        "path": parent.path,
        "description": "Use of HTTP without SSL/TLS - Insecure HTTP configuration in nested structure. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    au := glitch_lib.all_atomic_units(parent)[_]
    attr := au.attributes[_]
    walk(attr.value, [_, arr_node])
    arr_node.ir_type == "Array"
    elem := arr_node.value[_]
    elem.ir_type == "String"
    not is_multiline_string(elem)
    array_string_vulnerable(elem.value)
    result := {
        "type": "sec_https",
        "element": elem,
        "path": parent.path,
        "description": "Use of HTTP without SSL/TLS - Insecure HTTP indicator in array element. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    au := glitch_lib.all_atomic_units(parent)[_]
    attr := au.attributes[_]
    is_multiline_string(attr.value)
    str_lines := split(attr.value.value, "\n")
    line_content := str_lines[i]
    multiline_line_vulnerable(line_content)
    actual_line := attr.value.line + i
    result := {
        "type": "sec_https",
        "element": {"ir_type": "String", "line": actual_line, "value": line_content, "code": line_content},
        "path": parent.path,
        "description": "Use of HTTP without SSL/TLS - Insecure HTTP configuration in embedded content. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    ub := glitch_lib._gather_parent_unit_blocks[_]
    ub.path != ""
    var := ub.variables[_]
    kv_is_vulnerable(var)
    result := {
        "type": "sec_https",
        "element": var,
        "path": ub.path,
        "description": "Use of HTTP without SSL/TLS - Insecure HTTP configuration in variable. (CWE-319)"
    }
}