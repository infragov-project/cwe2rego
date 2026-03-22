package glitch

import data.glitch_lib

has_integrity_attr(node) {
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    regex.match("(?i)(checksum|hash|digest|sha256|sha512|sha384|sha1|md5|integrity|signature|fingerprint)", attr.name)
}

is_fetch_resource_type(t) {
    regex.match("(?i)^(remote_file|get_url|archive|wget|curl|download|tarball)$", t)
}

has_source_attr(node) {
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    regex.match("(?i)^(url|source|remote|src)$", attr.name)
}

has_url_string_attr(node) {
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match("(?i)^(https?|ftp|sftp)://", attr.value.value)
}

is_falsy(val) {
    val.ir_type == "Boolean"
    val.value == false
}

is_falsy(val) {
    val.ir_type == "String"
    regex.match("(?i)^(no|false|off|0)$", val.value)
}

is_truthy(val) {
    val.ir_type == "Boolean"
    val.value == true
}

is_truthy(val) {
    val.ir_type == "String"
    regex.match("(?i)^(yes|true|on|1)$", val.value)
}

has_integrity_bypass(node) {
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    regex.match("(?i)^(validate_certs|ssl_verify|verify_ssl|verify|pin_digest)$", attr.name)
    is_falsy(attr.value)
}

has_integrity_bypass(node) {
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    regex.match("(?i)^(insecure|skip_checksum|unsafe|no_verify|ignore_checksum|disable_integrity|allow_insecure_connections)$", attr.name)
    is_truthy(attr.value)
}

gpgcheck_disabled(value) {
    is_falsy(value)
}

gpgcheck_disabled(value) {
    value.ir_type == "Integer"
    value.value == 0
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    has_integrity_bypass(node)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Integrity or certificate verification explicitly disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    is_fetch_resource_type(node.type)
    has_source_attr(node)
    not has_integrity_attr(node)
    not has_integrity_bypass(node)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Remote resource fetched without integrity verification. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    not is_fetch_resource_type(node.type)
    has_url_string_attr(node)
    not has_integrity_attr(node)
    not has_integrity_bypass(node)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Remote resource fetched without integrity verification. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    lower(entry.key.value) == "gpgcheck"
    gpgcheck_disabled(entry.value)
    result := {
        "type": "sec_no_int_check",
        "element": entry.key,
        "path": parent.path,
        "description": "GPG check disabled - package integrity verification bypassed. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    lower(attr.name) == "gpgcheck"
    gpgcheck_disabled(attr.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "GPG check disabled - package integrity verification bypassed. (CWE-353)"
    }
}