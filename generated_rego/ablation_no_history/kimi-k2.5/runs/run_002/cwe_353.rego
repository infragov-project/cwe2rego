package glitch

import data.glitch_lib

integrity_keywords := {"checksum", "hash", "digest", "signature", "md5", "sha", "gpgcheck", "verify_checksum", "ssl_verify", "verify_ssl", "checksum_sha256", "checksum_sha1", "checksum_md5"}

validate_keywords := {"verify", "validate", "verify_ssl", "verify_peer", "strict_checking", "insecure", "skip_verify", "ssl_verify", "verify_checksum", "gpgcheck", "validate_certs", "insecure_skip_verify", "verify_strict"}

plain_protocols := {"telnet", "ftp", "http"}

download_resources := {"remote_file", "download", "get_url", "uri", "file", "uri_download"}

is_disabled(val) {
    val.ir_type == "Boolean"
    val.value == false
}

is_disabled(val) {
    val.ir_type == "Integer"
    val.value == 0
}

is_disabled(val) {
    val.ir_type == "String"
    regex.match("^(?i)(no|false|off|disabled|0)$", val.value)
}

is_disabled_or_absent(val) {
    is_disabled(val)
} else {
    val.ir_type == "Null"
} else {
    val.ir_type == "Undef"
}

has_http_without_integrity(val) {
    walk(val, [_, n])
    n.ir_type == "String"
    regex.match("(?i)^http://", n.value)
}

has_checksum_attr(attrs) {
    some a
    attrs[a].ir_type == "Attribute"
    regex.match(integrity_keywords[_], attrs[a].name)
    not is_disabled(attrs[a].value)
}

has_disabled_integrity_check(attrs) {
    some a
    attrs[a].ir_type == "Attribute"
    regex.match(validate_keywords[_], attrs[a].name)
    is_disabled(attrs[a].value)
}

check_hash_entries(entries) {
    some k
    entries[k].key.ir_type == "String"
    regex.match(validate_keywords[_], entries[k].key.value)
    is_disabled(entries[k].value)
}

find_integrity_disabled_in_any_value(val) {
    walk(val, [_, n])
    n.ir_type == "Hash"
    check_hash_entries(n.value)
}

find_integrity_disabled_in_any_value(val) {
    walk(val, [_, n])
    n.ir_type == "Attribute"
    regex.match(validate_keywords[_], n.name)
    is_disabled(n.value)
}

has_any_integrity_in_value(val) {
    walk(val, [_, n])
    n.ir_type == "Attribute"
    regex.match(integrity_keywords[_], n.name)
    not is_disabled(n.value)
}

has_any_integrity_in_value(val) {
    walk(val, [_, n])
    n.ir_type == "Hash"
    some k
    n.value[k].key.ir_type == "String"
    regex.match(integrity_keywords[_], n.value[k].key.value)
    not is_disabled(n.value[k].value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    aus := glitch_lib.all_atomic_units(parent)
    au := aus[_]
    au.type == download_resources[_]
    attrs := glitch_lib.all_attributes(au)
    has_disabled_integrity_check(attrs)
    not has_any_integrity_in_value(au)
    result := {
        "type": "sec_no_int_check",
        "element": au,
        "path": parent.path,
        "description": "Missing support for integrity check - Integrity verification disabled in download resource without alternative mechanism. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    aus := glitch_lib.all_atomic_units(parent)
    au := aus[_]
    au.type == download_resources[_]
    walk(au, [_, n])
    n.ir_type == "String"
    regex.match("(?i)^http://", n.value)
    not has_any_integrity_in_value(au)
    result := {
        "type": "sec_no_int_check",
        "element": au,
        "path": parent.path,
        "description": "Missing support for integrity check - Download from HTTP source without integrity verification. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    find_integrity_disabled_in_any_value(v.value)
    not has_any_integrity_in_value(v.value)
    result := {
        "type": "sec_no_int_check",
        "element": v,
        "path": parent.path,
        "description": "Missing support for integrity check - Integrity verification disabled in configuration without alternative mechanism. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    has_http_without_integrity(v.value)
    not has_any_integrity_in_value(v.value)
    result := {
        "type": "sec_no_int_check",
        "element": v,
        "path": parent.path,
        "description": "Missing support for integrity check - HTTP source configured without integrity verification. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "AtomicUnit"
    n.type == "remote_file"
    attrs := glitch_lib.all_attributes(n)
    count(attrs) > 0
    not has_checksum_attr(attrs)
    not has_any_integrity_in_value(n)
    result := {
        "type": "sec_no_int_check",
        "element": n,
        "path": parent.path,
        "description": "Missing support for integrity check - remote_file resource missing integrity verification mechanism. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, stmt])
    stmt.ir_type == "MethodCall"
    some i
    stmt.args[i].ir_type == "BlockExpr"
    walk(stmt.args[i], [_, au])
    au.ir_type == "AtomicUnit"
    au.type == "remote_file"
    not has_any_integrity_in_value(au)
    result := {
        "type": "sec_no_int_check",
        "element": au,
        "path": parent.path,
        "description": "Missing support for integrity check - remote_file resource in block missing integrity verification. (CWE-353)"
    }
}