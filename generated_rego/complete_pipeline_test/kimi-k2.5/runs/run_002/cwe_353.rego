package glitch

import data.glitch_lib

integrity_fields := {"checksum", "sha256", "md5", "hash", "digest", "signature", "sign", "gpg", "cosign", "content_digest", "checksum_sha256", "checksum_md5", "sha256sum", "md5sum", "sha1", "sha512", "gpg_key", "pgp_key", "sha256_checksum", "gpg_signature", "asc"}

bypass_attrs := {"gpgcheck", "repo_gpgcheck", "verify", "skip_verify", "insecure_skip_verify", "allow_unauthenticated"}

url_attrs := {"url", "source", "download_url", "package_url", "src", "uri", "address", "location", "baseurl", "mirrorlist"}

remote_execution_types := {"get_url", "download", "uri", "curl", "wget", "fetch", "unarchive", "archive", "pip", "npm", "gem", "maven", "docker_image", "remote_file", "http_request", "package", "yum", "apt", "zypper_repository"}

protocol_pattern := "(?i)^(http://|ftp://|git\\+http://|git://)"

check_disable(val) {
    val.ir_type == "Boolean"
    val.value == false
} else {
    val.ir_type == "Integer"
    val.value == 0
} else {
    val.ir_type == "String"
    regex.match("(?i)^(no|false|0|disabled|off)$", val.value)
}

has_protocol_any(node) {
    walk(node, [_, val])
    val.ir_type == "String"
    regex.match(protocol_pattern, val.value)
}

has_integrity_any(node) {
    walk(node, [_, attr])
    attr.ir_type == "Attribute"
    integrity_fields[lower(attr.name)]
    attr.value.ir_type != "Null"
    attr.value.ir_type != "Undef"
}

has_url_attr(node) {
    walk(node, [_, attr])
    attr.ir_type == "Attribute"
    url_attrs[lower(attr.name)]
}

hash_entry_has_bypass_disabled(hash_node) {
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    bypass_attrs[lower(entry.key.value)]
    check_disable(entry.value)
}

hash_node_has_bypass_disabled(node) {
    walk(node, [_, n])
    hash_entry_has_bypass_disabled(n)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, au])
    au.ir_type == "AtomicUnit"
    remote_execution_types[lower(au.type)]
    
    not has_integrity_any(au)
    
    result := {
        "type": "sec_no_int_check",
        "element": au,
        "path": parent.path,
        "description": "Missing support for integrity check - Remote resource retrieval without integrity verification. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, au])
    au.ir_type == "AtomicUnit"
    has_url_attr(au)
    has_protocol_any(au)
    not has_integrity_any(au)
    
    result := {
        "type": "sec_no_int_check",
        "element": au,
        "path": parent.path,
        "description": "Missing support for integrity check - Remote resource retrieval without integrity verification. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    hash_node_has_bypass_disabled(parent)
    
    bypass_kv := [kv |
        walk(parent, [_, n])
        n.ir_type == "Hash"
        entry := n.value[_]
        entry.key.ir_type == "String"
        bypass_attrs[lower(entry.key.value)]
        check_disable(entry.value)
        kv := entry.key
    ][_]
    
    result := {
        "type": "sec_no_int_check",
        "element": bypass_kv,
        "path": parent.path,
        "description": "Missing support for integrity check - Verification mechanism explicitly disabled. (CWE-353)"
    }
}