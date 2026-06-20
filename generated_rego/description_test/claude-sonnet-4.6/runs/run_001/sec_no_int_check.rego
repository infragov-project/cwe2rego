package glitch

import data.glitch_lib

has_integrity_attr(attrs) {
    attr := attrs[_]
    regex.match("(?i)^(checksum|sha256|sha512|md5|hash|digest|signature|gpg_key|pgp|integrity|expected_hash|content_hash|fingerprint|sign)$", attr.name)
}

value_contains_url(v) {
    walk(v, [_, n])
    n.ir_type == "String"
    regex.match("(?i)(https?|ftp)://", n.value)
}

value_contains_url(v) {
    walk(v, [_, n])
    n.ir_type == "VariableReference"
    regex.match("(?i)(url|uri|remote|download|endpoint)", n.value)
}

has_remote_source_attr(attrs) {
    attr := attrs[_]
    regex.match("(?i)^(url|source|src|download_url|remote_src|uri|fetch_url)$", attr.name)
    value_contains_url(attr.value)
}

is_download_resource(node) {
    regex.match("(?i)(remote_file|remote_directory|get_url|archive|download|fetch|retrieve)", node.type)
}

is_download_resource(node) {
    attrs := glitch_lib.all_attributes(node)
    has_remote_source_attr(attrs)
}

is_disabled(value) {
    value.ir_type == "Integer"
    value.value == 0
}

is_disabled(value) {
    value.ir_type == "Boolean"
    value.value == false
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    regex.match("(?i)^(verify|ssl_verify|tls_verify|validate_certs)$", attr.name)
    is_disabled(attr.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Download of code without integrity check - Verification explicitly disabled. (CWE-494)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    regex.match("(?i)^(insecure|skip_checksum|skip_verify)$", attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Download of code without integrity check - Insecure flag enabled. (CWE-494)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match("(?is).*(curl|wget|fetch).*[|].*(bash|sh)", attr.value.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Download of code without integrity check - Script piped to shell. (CWE-494)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    is_download_resource(node)
    attrs := glitch_lib.all_attributes(node)
    not has_integrity_attr(attrs)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Download of code without integrity check - Remote resource without integrity verification. (CWE-494)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    pair := hash_node.value[_]
    pair.key.ir_type == "String"
    regex.match("(?i)^(gpgcheck|gpg_check|verify|ssl_verify|validate_certs)$", pair.key.value)
    is_disabled(pair.value)
    result := {
        "type": "sec_no_int_check",
        "element": pair.key,
        "path": parent.path,
        "description": "Download of code without integrity check - GPG/integrity check disabled. (CWE-494)"
    }
}