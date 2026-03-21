package glitch

import data.glitch_lib

integrity_key_pattern := "(?i).*(checksum|check[_-]?sum|hash|digest|md5|sha|sha1|sha256|sha512|signature|signing|gpg|gpgcheck|pgp|hmac|etag|content[_-]?md5|verify|validation|integrity|require_hash|require_signature|tls|ssl|encryption|secure).*"
protocol_key_pattern := "(?i).*(protocol|transport|scheme|listener|endpoint).*"
transfer_type_pattern := "(?i).*(remote_file|remote_directory|get_url|uri|unarchive|archive|download|fetch|http_request|curl|wget).*"
transfer_key_pattern := "(?i).*(source|src|url|uri|endpoint|download|mirror|repo|repository|artifact|baseurl|mirrorlist).*"
url_hint_pattern := "(?i).*(http://|https://|ftp://|tftp://|s3://|gs://|scp://|rsync://|file://|://).*"
url_name_pattern := "(?i).*(url|uri|source|src|endpoint|download|mirror|repo|repository|artifact|baseurl|mirrorlist|link).*"
insecure_protocol_pattern := "(?i)(^http$|^ftp$|^tftp$|^udp$|^raw$|http://|ftp://|tftp://|cleartext|plain|insecure)"
disabled_value_pattern := "(?i)^(false|no|none|disabled|disable|off|skip|optional|0|n|nil)$"

is_integrity_key(name) {
    regex.match(integrity_key_pattern, name)
}

is_protocol_key(name) {
    regex.match(protocol_key_pattern, name)
}

key_name(expr) = name {
    expr.ir_type == "String"
    name = expr.value
} else = name {
    expr.ir_type == "VariableReference"
    name = expr.value
} else = name {
    expr.ir_type == "MethodCall"
    name = expr.method
} else = name {
    expr.ir_type == "FunctionCall"
    name = expr.name
} else = name {
    expr.ir_type == "Integer"
    name = sprintf("%v", [expr.value])
} else = name {
    name = ""
}

value_disabled(val) {
    [_, n] := walk(val)
    n.ir_type == "Boolean"
    n.value == false
} else {
    [_, n] := walk(val)
    n.ir_type == "Integer"
    n.value == 0
} else {
    [_, n] := walk(val)
    n.ir_type == "Float"
    n.value == 0
} else {
    [_, n] := walk(val)
    n.ir_type == "String"
    regex.match(disabled_value_pattern, n.value)
} else {
    [_, n] := walk(val)
    n.ir_type == "VariableReference"
    regex.match(disabled_value_pattern, n.value)
} else {
    [_, n] := walk(val)
    n.ir_type == "Null"
} else {
    [_, n] := walk(val)
    n.ir_type == "Undef"
}

value_has_url_hint(val) {
    [_, n] := walk(val)
    n.ir_type == "String"
    regex.match(url_hint_pattern, n.value)
} else {
    [_, n] := walk(val)
    n.ir_type == "VariableReference"
    regex.match(url_name_pattern, n.value)
} else {
    [_, n] := walk(val)
    n.ir_type == "MethodCall"
    regex.match(url_name_pattern, n.method)
} else {
    [_, n] := walk(val)
    n.ir_type == "FunctionCall"
    regex.match(url_name_pattern, n.name)
}

value_has_insecure_protocol(val) {
    [_, n] := walk(val)
    n.ir_type == "String"
    regex.match(insecure_protocol_pattern, n.value)
} else {
    [_, n] := walk(val)
    n.ir_type == "VariableReference"
    regex.match(insecure_protocol_pattern, n.value)
}

hash_has_transfer_key(h) {
    h.ir_type == "Hash"
    kv := h.value[_]
    name := key_name(kv.key)
    regex.match(transfer_key_pattern, name)
    value_has_url_hint(kv.value)
}

hash_has_integrity_key(h) {
    h.ir_type == "Hash"
    kv := h.value[_]
    name := key_name(kv.key)
    is_integrity_key(name)
}

has_integrity_key(node) {
    attr := glitch_lib.all_attributes(node)[_]
    is_integrity_key(attr.name)
} else {
    var := glitch_lib.all_variables(node)[_]
    is_integrity_key(var.name)
} else {
    [_, h] := walk(node)
    h.ir_type == "Hash"
    hash_has_integrity_key(h)
}

is_transfer_unit(unit) {
    regex.match(transfer_type_pattern, unit.type)
} else {
    attr := glitch_lib.all_attributes(unit)[_]
    regex.match(transfer_key_pattern, attr.name)
    value_has_url_hint(attr.value)
} else {
    [_, h] := walk(unit)
    h.ir_type == "Hash"
    kv := h.value[_]
    name := key_name(kv.key)
    regex.match(transfer_key_pattern, name)
    value_has_url_hint(kv.value)
}

has_insecure_protocol_setting(node) {
    attr := glitch_lib.all_attributes(node)[_]
    is_protocol_key(attr.name)
    value_has_insecure_protocol(attr.value)
} else {
    [_, h] := walk(node)
    h.ir_type == "Hash"
    kv := h.value[_]
    name := key_name(kv.key)
    is_protocol_key(name)
    value_has_insecure_protocol(kv.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attr := glitch_lib.all_attributes(parent)[_]
    is_integrity_key(attr.name)
    value_disabled(attr.value)

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Integrity verification disabled or optional. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    var := glitch_lib.all_variables(parent)[_]
    is_integrity_key(var.name)
    value_disabled(var.value)

    result := {
        "type": "sec_no_int_check",
        "element": var,
        "path": parent.path,
        "description": "Missing support for integrity check - Integrity verification disabled or optional. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    [_, h] := walk(parent)
    h.ir_type == "Hash"
    kv := h.value[_]
    name := key_name(kv.key)
    is_integrity_key(name)
    value_disabled(kv.value)

    result := {
        "type": "sec_no_int_check",
        "element": kv.value,
        "path": parent.path,
        "description": "Missing support for integrity check - Integrity verification disabled or optional. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    unit := glitch_lib.all_atomic_units(parent)[_]
    is_transfer_unit(unit)
    not has_integrity_key(unit)

    result := {
        "type": "sec_no_int_check",
        "element": unit,
        "path": parent.path,
        "description": "Missing support for integrity check - Data or artifact transfer without integrity verification. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    [_, h] := walk(parent)
    h.ir_type == "Hash"
    hash_has_transfer_key(h)
    not hash_has_integrity_key(h)

    result := {
        "type": "sec_no_int_check",
        "element": h,
        "path": parent.path,
        "description": "Missing support for integrity check - Data or artifact transfer without integrity verification. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    unit := glitch_lib.all_atomic_units(parent)[_]
    has_insecure_protocol_setting(unit)
    not has_integrity_key(unit)

    result := {
        "type": "sec_no_int_check",
        "element": unit,
        "path": parent.path,
        "description": "Missing support for integrity check - Insecure protocol configured without integrity protection. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    [_, h] := walk(parent)
    h.ir_type == "Hash"
    kv := h.value[_]
    name := key_name(kv.key)
    is_protocol_key(name)
    value_has_insecure_protocol(kv.value)
    not hash_has_integrity_key(h)

    result := {
        "type": "sec_no_int_check",
        "element": kv.value,
        "path": parent.path,
        "description": "Missing support for integrity check - Insecure protocol configured without integrity protection. (CWE-353)"
    }
}