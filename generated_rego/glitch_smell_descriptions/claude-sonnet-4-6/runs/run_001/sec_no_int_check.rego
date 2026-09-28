package glitch

import data.glitch_lib

is_url_attr_name(name) {
    regex.match(`(?i)^(url|source|download_url|remote_file|source_url|remote_source|archive_url|src)$`, name)
}

is_integrity_attr_name(name) {
    regex.match(`(?i)(checksum|sha256|sha512|md5sum|md5|hash|integrity|verify|digest|expected_hash|content_hash|gpg_key|pgp_key|signature|gpgcheck)`, name)
}

is_remote_url(value) {
    value.ir_type == "String"
    regex.match(`(?i)^(https?|ftp)://`, value.value)
}

is_placeholder_value(value) {
    value.ir_type == "String"
    value.value == ""
}

is_placeholder_value(value) {
    value.ir_type == "String"
    regex.match(`(?i)^(none|null|false|n/a|todo|undefined)$`, value.value)
}

is_placeholder_value(value) {
    value.ir_type == "Null"
}

is_placeholder_value(value) {
    value.ir_type == "Boolean"
    value.value == false
}

is_placeholder_value(value) {
    value.ir_type == "Integer"
    value.value == 0
}

has_integrity_attr(node) {
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_integrity_attr_name(attr.name)
    not is_placeholder_value(attr.value)
}

is_download_type(t) {
    regex.match(`(?i)(remote_file|get_url|http_source|download|fetch|archive|remote_package)`, t)
}

all_atomic_units_deep(node) = units {
    units = {n |
        walk(node, [_, n])
        n.ir_type == "AtomicUnit"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := all_atomic_units_deep(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.value.ir_type == "String"
    regex.match(`(?i)(curl|wget|fetch).+\|.*(bash|sh|zsh|fish|ksh|csh)`, attr.value.value)

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "No integrity check on downloaded content - Piping downloads directly to a shell interpreter bypasses integrity verification. (CWE-494)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := all_atomic_units_deep(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    is_url_attr_name(attr.name)
    is_remote_url(attr.value)
    not has_integrity_attr(node)

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "No integrity check on downloaded content - Remote resources should be verified using checksums or cryptographic signatures. (CWE-494)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := all_atomic_units_deep(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.value.ir_type == "String"
    regex.match(`(?i)(pip install|npm install|gem install|apt-get install|yum install|brew install)`, attr.value.value)
    not regex.match(`(?i)(--hash=|integrity|--require-hashes)`, attr.value.value)

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "No integrity check on downloaded content - Package manager invoked without hash pinning or integrity verification flags. (CWE-494)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := all_atomic_units_deep(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    is_url_attr_name(attr.name)
    attr.value.ir_type == "String"
    regex.match(`^http://`, attr.value.value)

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "No integrity check on downloaded content - Downloading resources over unencrypted HTTP exposes the transfer to tampering. (CWE-494)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := all_atomic_units_deep(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    is_integrity_attr_name(attr.name)
    is_placeholder_value(attr.value)

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "No integrity check on downloaded content - Integrity field contains a placeholder or disabled value. (CWE-494)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := all_atomic_units_deep(parent)
    node := atomic_units[_]

    is_download_type(node.type)
    not has_integrity_attr(node)

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "No integrity check on downloaded content - Download resource lacks integrity verification attributes. (CWE-494)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"

    pair := hash_node.value[_]
    pair.key.ir_type == "String"
    is_integrity_attr_name(pair.key.value)
    is_placeholder_value(pair.value)

    result := {
        "type": "sec_no_int_check",
        "element": pair.value,
        "path": parent.path,
        "description": "No integrity check on downloaded content - Integrity verification field contains a placeholder or disabled value in configuration. (CWE-494)"
    }
}