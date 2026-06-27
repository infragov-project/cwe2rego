package glitch

import data.glitch_lib

integrity_keys := {"gpgcheck", "validate_certs", "ssl_verify", "verify_ssl", "verify_peer"}

download_types := {"get_url", "download", "remote_file", "git", "archive", "uri", "fetch", "wget", "curl", "repo", "yum_repository", "apt_repository"}

integrity_indicators := {"checksum", "sha256", "sha256sum", "sha1", "sha1sum", "md5", "md5sum", "hash", "digest", "verify_checksum", "checksum_file", "checksum_url", "gpgkey"}

url_attrs := {"url", "source", "src", "uri", "baseurl", "mirrorlist", "location", "href"}

disabled_strings := {"no", "false", "off", "0", "disable", "disabled"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    has_url_or_is_download(node)
    not has_integrity_attribute(node)
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing support for integrity check - Data transmission without integrity verification mechanism (checksum/hash/GPG validation) enables undetected tampering. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node_has_disabled_integrity(node)
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing support for integrity check - Disabled integrity verification mechanism (gpgcheck/validate_certs/ssl_verify) enables undetected tampering. (CWE-353)"
    }
}

has_url_or_is_download(node) {
    download_types[lower(node.type)]
}

has_url_or_is_download(node) {
    walk(node, [_, item])
    item_has_url(item)
}

item_has_url(item) {
    item.ir_type == "Attribute"
    url_attrs[lower(item.name)]
}

item_has_url(item) {
    item.ir_type == "KeyValue"
    url_key(item.key)
}

item_has_url(item) {
    item.ir_type == "String"
    regex.match("^(https?|ftp)://", item.value)
} else {
    item.ir_type == "String"
    url_attrs[lower(item.value)]
}

url_key(key) {
    key.ir_type == "String"
    url_attrs[lower(key.value)]
}

url_key(key) {
    key.ir_type == "VariableReference"
    url_attrs[lower(key.value)]
}

has_integrity_attribute(node) {
    walk(node, [_, item])
    item_marks_integrity(item)
}

item_marks_integrity(item) {
    item.ir_type == "Attribute"
    integrity_indicators[lower(item.name)]
}

item_marks_integrity(item) {
    item.ir_type == "KeyValue"
    integrity_key(item.key)
}

integrity_key(key) {
    key.ir_type == "String"
    integrity_indicators[lower(key.value)]
}

integrity_key(key) {
    key.ir_type == "VariableReference"
    integrity_indicators[lower(key.value)]
}

node_has_disabled_integrity(node) {
    node.ir_type == "Attribute"
    integrity_keys[lower(node.name)]
    value_is_disabled(node.value)
}

node_has_disabled_integrity(node) {
    node.ir_type == "KeyValue"
    integrity_key_match(node.key)
    value_is_disabled(node.value)
}

integrity_key_match(key) {
    key.ir_type == "String"
    integrity_keys[lower(key.value)]
}

integrity_key_match(key) {
    key.ir_type == "VariableReference"
    integrity_keys[lower(key.value)]
}

value_is_disabled(value) {
    value.ir_type == "Integer"
    value.value == 0
}

value_is_disabled(value) {
    value.ir_type == "String"
    disabled_strings[lower(value.value)]
}

value_is_disabled(value) {
    value.ir_type == "Boolean"
    value.value == false
}