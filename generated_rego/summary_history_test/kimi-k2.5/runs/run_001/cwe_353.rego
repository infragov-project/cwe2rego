package glitch

import data.glitch_lib

download_types := {"get_url", "uri", "s3_object", "ec2_object", "remote_file", "http_request", "fetch_url", "download", "package", "archive", "unarchive", "gem_package", "npm_package", "pip_package", "wget", "curl", "yum_repository", "apt_repository", "zypper_repository", "rpm_key", "apt_key"}

integrity_keywords := {"checksum", "checksum_url", "checksum_type", "hash", "digest", "sha256", "sha256sum", "256", "sha256_hash", "md5", "md5sum", "md5_hash", "sha1", "sha1sum", "sha1_hash", "signature", "gpg_key", "gpgkey", "signed_by", "signing_key", "validate_checksum", "verify_checksum", "checksum_verification", "source_hash", "expected_hash", "content_hash", "artifact_digest", "image_digest", "integrity", "gpg_signature", "signature_file", "verify", "checksum_file", "gpg_keys", "key", "gpg"}

is_disabled_value(val) {
    val.ir_type == "Boolean"
    val.value == false
} else {
    val.ir_type == "Integer"
    val.value == 0
} else {
    val.ir_type == "String"
    lower(val.value) == "false"
} else {
    val.ir_type == "String"
    val.value == "0"
} else {
    val.ir_type == "String"
    lower(val.value) == "no"
}

is_disabled_integrity_key(key_str) {
    lk := lower(key_str)
    contains(lk, "gpgcheck")
} else {
    lk := lower(key_str)
    contains(lk, "repo_gpgcheck")
} else {
    lk := lower(key_str)
    contains(lk, "pkg_check")
} else {
    lk := lower(key_str)
    contains(lk, "verify_checksum")
} else {
    lk := lower(key_str)
    contains(lk, "verify_digest")
} else {
    lk := lower(key_str)
    contains(lk, "enforce_integrity")
}

is_valid_integrity_value(val) {
    val.ir_type == "String"
    val.value != ""
    val.value != "null"
    val.value != "nil"
    val.value != "undef"
} else {
    val.ir_type != "String"
    val.ir_type != "Undef"
    val.ir_type != "Null"
    not is_disabled_value(val)
}

has_url_in_code(code_str) {
    regex.match("(?i)(https?|ftps?)://", code_str)
}

has_url_in_expression(expr) {
    walk(expr, [_, n])
    n.ir_type == "String"
    has_url_in_code(n.value)
} else {
    walk(expr, [_, n])
    n.ir_type == "VariableReference"
    contains(lower(n.value), "url")
}

has_source_attribute(au) {
    walk(au, [_, n])
    n.ir_type == "Attribute"
    lower(n.name) == "source"
    has_url_in_expression(n.value)
}

has_any_url_reference(au) {
    walk(au, [_, n])
    n.ir_type == "String"
    has_url_in_code(n.value)
} else {
    walk(au, [_, n])
    n.ir_type == "VariableReference"
    contains(lower(n.value), "url")
} else {
    walk(au, [_, n])
    contains(lower(n.code), "url")
}

is_download_type(type_str) {
    lt := lower(type_str)
    dt := download_types[_]
    contains(lt, dt)
}

is_integrity_attribute_name(name) {
    lower_name := lower(name)
    ik := integrity_keywords[_]
    contains(lower_name, ik)
}

has_integrity_attribute(au) {
    walk(au, [_, n])
    n.ir_type == "Attribute"
    is_integrity_attribute_name(n.name)
    is_valid_integrity_value(n.value)
}

has_integrity_in_hash(node) {
    walk(node, [_, n])
    n.ir_type == "Hash"
    entry := n.value[_]
    entry.key.ir_type == "String"
    is_integrity_attribute_name(entry.key.value)
    is_valid_integrity_value(entry.value)
}

has_any_integrity(au) {
    has_integrity_attribute(au)
} else {
    has_integrity_in_hash(au)
}

is_remote_download_type(au) {
    is_download_type(au.type)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    
    is_remote_download_type(au)
    has_any_url_reference(au)
    not has_any_integrity(au)
    
    result := {
        "type": "sec_no_int_check",
        "element": au,
        "path": parent.path,
        "description": "Missing support for integrity check - Remote resource fetch without integrity verification. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    walk(var, [_, n])
    n.ir_type == "Hash"
    entry := n.value[_]
    entry.key.ir_type == "String"
    key_str := entry.key.value
    is_disabled_integrity_key(key_str)
    is_disabled_value(entry.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": entry.key,
        "path": parent.path,
        "description": "Missing support for integrity check - Integrity verification explicitly disabled. (CWE-353)"
    }
}