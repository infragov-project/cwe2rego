package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    is_download_or_extract_operation(node.type)

    attrs := glitch_lib.all_attributes(node)
    
    has_remote_source(attrs)
    
    not has_integrity_check(attrs)
    
    not is_local_only_operation(attrs)

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing support for integrity check - Data transmission without checksum or integrity verification mechanism. (CWE-353)"
    }
}

is_download_or_extract_operation(au_type) {
    keywords := {"download", "get", "fetch", "pull", "wget", "curl", "unarchive", "unzip", "extract", "tar", "untar"}
    glitch_lib.contains(lower(au_type), keywords[_])
}

has_remote_source(attrs) {
    attr := attrs[_]
    source_names := {"source", "url", "uri", "src", "location", "download", "repo", "repository"}
    attr.name == source_names[_]
    
    is_remote_value(attr.value)
}

is_remote_value(val) {
    val.ir_type == "String"
    remote_schemes := {"http://", "https://", "ftp://", "scp://", "sftp://", "git://", "ssh://"}
    starts_with_any(val.value, remote_schemes)
}

is_remote_value(val) {
    val.ir_type == "String"
    not starts_with_any(val.value, {"/", "./", "../", "file://"})
    regex.match("^[^/]+\\.[^/]+", val.value)
}

starts_with_any(str, prefixes) {
    prefix := prefixes[_]
    startswith(str, prefix)
}

has_integrity_check(attrs) {
    attr := attrs[_]
    integrity_attrs := {"checksum", "checksums", "sha256", "sha256sum", "sha1", "md5", "hash", "verify_checksum", "validate_checksum", "integrity", "signature", "sig", "checksum_verification"}
    attr.name == integrity_attrs[_]
    not_null_or_false(attr.value)
}

not_null_or_false(val) {
    not val.ir_type == "Null"
}

not_null_or_false(val) {
    not val.ir_type == "Undef"
}

not_null_or_false(val) {
    val.ir_type == "Boolean"
    val.value == true
}

not_null_or_false(val) {
    val.ir_type == "String"
    val.value != ""
}

is_local_only_operation(attrs) {
    attr := attrs[_]
    attr.name == "source"
    attr.value.ir_type == "String"
    local_prefixes := {"/", "./", "../", "file://"}
    starts_with_any(attr.value.value, local_prefixes)
}