package glitch

import data.glitch_lib

insecure_protocol_patterns := {"ftp://", "http://", "telnet://", "smtp://", "pop://", "imap://", "gopher://", "tftp://"}

int_check_attrs := {"checksum", "sha256", "sha512", "md5", "hash", "integrity", "gpgcheck", "verify_checksum", "check_signature", "verify", "checksum_mode", "checksum_algorithm", "expected_checksum", "sha1", "sha224", "sha384", "sha256sum", "md5sum", "gpg_key", "key", "signature", "signature_algorithm", "digest", "digest_type", "verify_type", "verify_mode", "validate", "strict", "gpg_verify", "ssl_verify", "verify_ssl", "validate_certs", "insecure", "ssl_verify_mode", "verify_peer", "tls", "tls_verify", "ca_cert", "cacert", "ca_file", "ca_path", "client_cert", "client_key"}

url_attrs := {"url", "source", "src", "download_url", "uri", "baseurl", "mirrorlist", "repository", "base_url", "src_url", "file", "download", "archive_url", "package_url", "oracle_url"}

is_insecure_protocol(str) {
    pattern := insecure_protocol_patterns[_]
    startswith(lower(str), pattern)
}

has_insecure_protocol_in_any_string(root) {
    walk(root, [_, n])
    n.ir_type == "String"
    is_insecure_protocol(n.value)
}

is_disabled_value(val_node) {
    val_node.ir_type == "Boolean"
    val_node.value == false
}

is_disabled_value(val_node) {
    val_node.ir_type == "Integer"
    val_node.value == 0
}

is_disabled_value(val_node) {
    val_node.ir_type == "String"
    lower(val_node.value) == "false"
}

is_disabled_value(val_node) {
    val_node.ir_type == "String"
    lower(val_node.value) == "no"
}

is_disabled_value(val_node) {
    val_node.ir_type == "String"
    lower(val_node.value) == "off"
}

is_disabled_value(val_node) {
    val_node.ir_type == "String"
    lower(val_node.value) == "0"
}

is_disabled_value(val_node) {
    val_node.ir_type == "String"
    lower(val_node.value) == "null"
}

is_disabled_value(val_node) {
    val_node.ir_type == "Null"
}

is_disabled_value(val_node) {
    val_node.ir_type == "Undef"
}

find_disabled_in_structure(root, key_names) {
    walk(root, [_, child])
    child.ir_type == "KeyValue"
    child.name == key_names[_]
    is_disabled_value(child.value)
}

find_disabled_in_structure(root, key_names) {
    walk(root, [_, child])
    child.ir_type == "Attribute"
    child.name == key_names[_]
    is_disabled_value(child.value)
}

find_disabled_in_structure(root, key_names) {
    walk(root, [_, child])
    child.ir_type == "Hash"
    child.value[kv]
    kv.ir_type == "KeyValue"
    kv.name == key_names[_]
    is_disabled_value(kv.value)
}

has_insecure_url_in_structure(root) {
    walk(root, [_, child])
    child.ir_type == "KeyValue"
    child.name == url_attrs[_]
    has_insecure_protocol_in_any_string(child.value)
}

has_insecure_url_in_structure(root) {
    walk(root, [_, child])
    child.ir_type == "Attribute"
    child.name == url_attrs[_]
    has_insecure_protocol_in_any_string(child.value)
}

is_download_or_remote_type(type_str) {
    lower(type_str) == "remote_file"
}

is_download_or_remote_type(type_str) {
    lower(type_str) == "get_url"
}

is_download_or_remote_type(type_str) {
    lower(type_str) == "fetch"
}

is_download_or_remote_type(type_str) {
    lower(type_str) == "archive"
}

is_download_or_remote_type(type_str) {
    lower(type_str) == "download"
}

is_download_or_remote_type(type_str) {
    lower(type_str) == "uri"
}

is_download_or_remote_type(type_str) {
    lower(type_str) == "s3_file"
}

is_download_or_remote_type(type_str) {
    lower(type_str) == "yum_repository"
}

is_download_or_remote_type(type_str) {
    lower(type_str) == "apt_repository"
}

is_download_or_remote_type(type_str) {
    lower(type_str) == "zypper_repository"
}

is_download_or_remote_type(type_str) {
    lower(type_str) == "rpm_key"
}

is_download_or_remote_type(type_str) {
    lower(type_str) == "gpg_key"
}

is_download_or_remote_type(type_str) {
    lower(type_str) == "repository"
}

is_download_or_remote_type(type_str) {
    lower(type_str) == "java_oracle"
}

has_source_or_url_attr(node) {
    walk(node, [_, child])
    child.ir_type == "Attribute"
    child.name == url_attrs[_]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, var])
    var.ir_type == "Variable"
    find_disabled_in_structure(var, int_check_attrs)
    
    result := {
        "type": "sec_no_int_check",
        "element": var,
        "path": parent.path,
        "description": "Missing support for integrity check - Variable contains disabled integrity verification configuration. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, var])
    var.ir_type == "Variable"
    find_disabled_in_structure(var.value, int_check_attrs)
    
    result := {
        "type": "sec_no_int_check",
        "element": var,
        "path": parent.path,
        "description": "Missing support for integrity check - Variable contains disabled integrity verification configuration. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, ub])
    ub.ir_type == "UnitBlock"
    find_disabled_in_structure(ub, int_check_attrs)
    
    result := {
        "type": "sec_no_int_check",
        "element": ub,
        "path": parent.path,
        "description": "Missing support for integrity check - Configuration block contains disabled integrity verification. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    is_download_or_remote_type(au.type)
    find_disabled_in_structure(au, int_check_attrs)
    
    result := {
        "type": "sec_no_int_check",
        "element": au,
        "path": parent.path,
        "description": "Missing support for integrity check - Remote operation has disabled integrity verification attribute. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, au])
    au.ir_type == "AtomicUnit"
    is_download_or_remote_type(au.type)
    has_insecure_url_in_structure(au)
    
    result := {
        "type": "sec_no_int_check",
        "element": au,
        "path": parent.path,
        "description": "Missing support for integrity check - Remote resource uses insecure protocol (HTTP/FTP). (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, au])
    au.ir_type == "AtomicUnit"
    is_download_or_remote_type(au.type)
    has_source_or_url_attr(au)
    
    result := {
        "type": "sec_no_int_check",
        "element": au,
        "path": parent.path,
        "description": "Missing support for integrity check - Remote file operation may lack integrity verification. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, au])
    au.ir_type == "AtomicUnit"
    lower(au.type) == "remote_file"
    
    result := {
        "type": "sec_no_int_check",
        "element": au,
        "path": parent.path,
        "description": "Missing support for integrity check - Remote file operation without explicit integrity verification. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, au])
    au.ir_type == "AtomicUnit"
    lower(au.type) == "archive"
    has_source_or_url_attr(au)
    
    result := {
        "type": "sec_no_int_check",
        "element": au,
        "path": parent.path,
        "description": "Missing support for integrity check - Archive download without explicit integrity verification. (CWE-353)"
    }
}