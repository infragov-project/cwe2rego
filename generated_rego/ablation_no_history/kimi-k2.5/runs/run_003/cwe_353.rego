package glitch

import data.glitch_lib

disabled_values := {"false", "no", "0", "off", "disable", "disabled", "none", "null", "skip", "bypass", "ignore", "never"}

verify_disable_attrs := {"validate_certs", "verify", "gpgcheck", "ssl_verify", "tls_verify", "strict_host_key_checking", "host_key_checking", "check_signature", "use_gpg", "verify_ssl", "verify_peer"}

integrity_attrs := {"checksum", "digest", "sha256", "md5", "hash", "integrity", "signature", "sha1", "sha512", "gpgkey", "key_url", "checksum_sha256", "checksum_md5", "remote_checksum", "checksum_url", "gpgcheck_url"}

download_types := {"get_url", "url", "source", "download", "remote_file", "uri", "file", "template", "copy", "unarchive", "git", "package", "yumpackage", "aptpackage", "dpkg_package", "rpm_package"}

is_disabled_value(val) {
    val.ir_type == "Boolean"
    val.value == false
} else {
    val.ir_type == "Integer"
    val.value == 0
} else {
    val.ir_type == "String"
    contains(lower(val.value), disabled_values[_])
}

has_integrity_attr(node) {
    walk(node, [_, attr])
    attr.ir_type == "Attribute"
    contains(lower(attr.name), integrity_attrs[_])
    not is_null_or_undef(attr.value)
}

is_null_or_undef(val) {
    val.ir_type == "Null"
} else {
    val.ir_type == "Undef"
}

is_remote_protocol(val) {
    val.ir_type == "String"
    lower_content := lower(val.value)
    regex.match("^https?://", lower_content)
    not startswith(lower_content, "file://")
    not startswith(val.value, "/")
} else {
    val.ir_type == "String"
    lower_content := lower(val.value)
    regex.match("^(ftp|sftp|rsync)://", lower_content)
}

has_remote_source(node) {
    walk(node, [_, attr])
    attr.ir_type == "Attribute"
    attr.name == "url"
    is_remote_protocol(attr.value)
} else {
    walk(node, [_, attr])
    attr.ir_type == "Attribute"
    attr.name == "source"
    is_remote_protocol(attr.value)
} else {
    walk(node, [_, attr])
    attr.ir_type == "Attribute"
    attr.name == "baseurl"
    is_remote_protocol(attr.value)
}

is_download_type(au_type) {
    contains(lower(au_type), download_types[_])
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, kv])
    kv.ir_type == "KeyValue"
    lower(kv.key.value) == verify_disable_attrs[_]
    is_disabled_value(kv.value)

    result := {
        "type": "sec_no_int_check",
        "element": kv,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Integrity verification mechanism disabled in configuration. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, attr])
    attr.ir_type == "Attribute"
    lower(attr.name) == verify_disable_attrs[_]
    is_disabled_value(attr.value)

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Integrity verification mechanism disabled in configuration. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, au])
    au.ir_type == "AtomicUnit"
    is_download_type(au.type)
    has_remote_source(au)
    not has_integrity_attr(au)

    result := {
        "type": "sec_no_int_check",
        "element": au,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Remote resource downloaded without integrity verification mechanism. (CWE-353)"
    }
}