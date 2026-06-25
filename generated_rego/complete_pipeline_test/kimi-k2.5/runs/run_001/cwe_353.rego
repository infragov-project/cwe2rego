package glitch

import data.glitch_lib

unsafe_protocols := {"http://", "ftp://", "telnet://"}
integrity_attrs := {"checksum", "hash", "sha256", "sha512", "md5", "signature", "gpgkey", "verify_ssl", "verify_peer", "ssl_verify", "tls_verify", "validate_certs", "strict_host_key", "integrity", "digest", "fingerprint", "creates", "not_if", "only_if"}
integrity_disabled := {"verify_ssl", "ssl_verify", "tls_verify", "validate_certs", "strict_host_key_checking", "gpgcheck", "repo_gpgcheck", "sslverify", "insecure", "insecure_skip_verify", "tls_skip_verify", "disable_checksum", "checksum_verification", "verify_checksum", "verify_peer", "verify", "ssl_verification", "tls_verification"}

is_integrity_disabled_attr(name) {
    lower_name := lower(name)
    integrity_disabled[_] == lower_name
}

is_integrity_disabled_attr(name) {
    lower_name := lower(name)
    contains(lower_name, "gpgcheck")
}

is_integrity_disabled_attr(name) {
    lower_name := lower(name)
    contains(lower_name, "verify")
    contains(lower_name, "ssl")
}

is_integrity_disabled_attr(name) {
    lower_name := lower(name)
    contains(lower_name, "verify")
    contains(lower_name, "tls")
}

is_disabled_value(val) {
    val.ir_type == "Boolean"
    val.value == false
}

is_disabled_value(val) {
    val.ir_type == "Integer"
    val.value == 0
}

is_disabled_value(val) {
    val.ir_type == "String"
    lower_val := lower(val.value)
    {"false", "no", "0", "disabled", "off", "skip"}[lower_val]
}

is_integrity_attr(name) {
    lower_name := lower(name)
    integrity_attrs[_] == lower_name
}

has_any_integrity_keyword(code_str) {
    keyword := integrity_attrs[_]
    contains(lower(code_str), keyword)
}

has_unsafe_protocol(str_val) {
    proto := unsafe_protocols[_]
    contains(lower(str_val), proto)
}

code_has_unsafe_protocol(code_str) {
    contains(lower(code_str), "http://")
}

code_has_unsafe_protocol(code_str) {
    contains(lower(code_str), "ftp://")
}

code_has_unsafe_protocol(code_str) {
    contains(lower(code_str), "telnet://")
}

is_download_resource_type(type_str) {
    lower_type := lower(type_str)
    contains(lower_type, "remote_file")
}

is_download_resource_type(type_str) {
    lower_type := lower(type_str)
    contains(lower_type, "archive")
}

is_download_resource_type(type_str) {
    lower_type := lower(type_str)
    contains(lower_type, "download")
}

is_download_resource_type(type_str) {
    lower_type := lower(type_str)
    contains(lower_type, "get_url")
}

is_download_resource_type(type_str) {
    lower_type := lower(type_str)
    contains(lower_type, "wget")
}

is_download_resource_type(type_str) {
    lower_type := lower(type_str)
    contains(lower_type, "curl")
}

is_download_resource_type(type_str) {
    lower_type := lower(type_str)
    contains(lower_type, "get")
}

check_disabled_integrity_entry(key, val) {
    key.ir_type == "String"
    is_integrity_disabled_attr(key.value)
    is_disabled_value(val)
}

match_disabled_integrity(node) {
    node.ir_type == "Hash"
    entry := node.value[_]
    check_disabled_integrity_entry(entry.key, entry.value)
}

match_disabled_integrity(node) {
    node.ir_type == "Hash"
    entry := node.value[_]
    nested := entry.value
    nested.ir_type == "Hash"
    inner_entry := nested.value[_]
    check_disabled_integrity_entry(inner_entry.key, inner_entry.value)
}

match_disabled_integrity(node) {
    node.ir_type == "Variable"
    node.value.ir_type == "Hash"
    entry := node.value.value[_]
    check_disabled_integrity_entry(entry.key, entry.value)
}

match_disabled_integrity(node) {
    node.ir_type == "Variable"
    node.value.ir_type == "Hash"
    entry := node.value.value[_]
    nested := entry.value
    nested.ir_type == "Hash"
    inner_entry := nested.value[_]
    check_disabled_integrity_entry(inner_entry.key, inner_entry.value)
}

contains_integrity_keyword_in_code(code_str) {
    code_str != ""
    has_any_integrity_keyword(code_str)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, n])
    match_disabled_integrity(n)

    n.line > 0

    result := {
        "type": "sec_no_int_check",
        "element": n,
        "path": parent.path,
        "description": "Missing support for integrity check - Integrity verification disabled in configuration (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, au])
    au.ir_type == "AtomicUnit"

    is_download_resource_type(au.type)
    au.code != ""
    code_has_unsafe_protocol(au.code)
    not contains_integrity_keyword_in_code(au.code)

    au.line > 0

    result := {
        "type": "sec_no_int_check",
        "element": au,
        "path": parent.path,
        "description": "Missing support for integrity check - Download resource using unsafe protocol without integrity verification (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, mc])
    mc.ir_type == "MethodCall"

    mc.code != ""
    contains(lower(mc.code), "remote_file")
    code_has_unsafe_protocol(mc.code)
    not contains_integrity_keyword_in_code(mc.code)

    mc.line > 0

    result := {
        "type": "sec_no_int_check",
        "element": mc,
        "path": parent.path,
        "description": "Missing support for integrity check - Remote file download with unsafe protocol and no integrity verification (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, be])
    be.ir_type == "BlockExpr"

    be.code != ""
    contains(lower(be.code), "remote_file")
    code_has_unsafe_protocol(be.code)
    not contains_integrity_keyword_in_code(be.code)

    be.line > 0

    result := {
        "type": "sec_no_int_check",
        "element": be,
        "path": parent.path,
        "description": "Missing support for integrity check - Remote file block with unsafe protocol and no integrity verification (CWE-353)"
    }
}