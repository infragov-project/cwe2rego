package glitch

import data.glitch_lib
import future.keywords.in

integrity_indicators := {"checksum", "sha256", "sha1", "sha512", "md5", "hash", "digest", "verify", "validation", "integrity", "signature", "sign", "fingerprint", "checksum_url"}
gpgcheck_keys := {"gpgcheck", "repo_gpgcheck"}
download_indicators := {"url", "source", "uri", "location", "endpoint", "download_url", "src", "baseurl", "mirrorlist"}
image_indicators := {"image", "container_image", "docker_image"}
bypass_flags := {"gpgcheck", "repo_gpgcheck", "allow_unauthenticated", "trusted", "insecure_skip_verify", "verify_ssl", "verify_peer", "ssl_verify", "verify"}
floating_tags := {"latest", "stable", "nightly", "beta", "alpha", "dev", "edge", "master", "main", "develop", "preview", "canary", "rc", "slim"}
download_resource_types := {"get_url", "remote_file", "download", "uri", "curl", "wget", "fetch", "archive", "remote_directory", "remote_file", "file"}

is_disabled_value(value) {
    value.ir_type == "Integer"
    value.value == 0
}

is_disabled_value(value) {
    value.ir_type == "Boolean"
    value.value == false
}

is_disabled_value(value) {
    value.ir_type == "String"
    lowered := lower(value.value)
    lowered in {"no", "false", "0", "off", "disabled"}
}

is_floating_tag(s) {
    parts := split(s, ":")
    count(parts) >= 2
    tag := lower(trim_space(parts[count(parts) - 1]))
    tag in floating_tags
}

is_http_url(s) {
    lower(s) == "http"
}

is_http_url(s) {
    startswith(lower(s), "http://")
}

is_http_url(s) {
    startswith(lower(s), "http:")
}

is_ftp_url(s) {
    startswith(lower(s), "ftp://")
}

is_ftp_url(s) {
    startswith(lower(s), "ftp:")
}

has_insecure_protocol_string(s) {
    is_http_url(s)
}

has_insecure_protocol_string(s) {
    is_ftp_url(s)
}

any_string_has_insecure_protocol(node) {
    [_, n] := walk(node)
    n.ir_type == "String"
    has_insecure_protocol_string(n.value)
}

any_var_ref_exists(node) {
    [_, n] := walk(node)
    n.ir_type == "VariableReference"
}

has_docker_digest(s) {
    contains(lower(s), "@sha256:")
}

has_docker_digest(s) {
    contains(lower(s), "@sha512:")
}

has_docker_digest(s) {
    contains(lower(s), "@")
}

any_string_has_floating_tag(node) {
    [_, n] := walk(node)
    n.ir_type == "String"
    contains(n.value, ":")
    not has_docker_digest(n.value)
    is_floating_tag(n.value)
}

has_integrity_attribute(node) {
    [_, n] := walk(node)
    n.ir_type == "Attribute"
    lower(n.name) in integrity_indicators
}

has_checksum_in_hash(node) {
    [_, n] := walk(node)
    n.ir_type == "Hash"
    some kv in n.value
    kv.key.ir_type == "String"
    lower(kv.key.value) in integrity_indicators
}

is_external_download_resource(node) {
    lr := lower(node.type)
    lr in download_resource_types
}

is_external_download_resource(node) {
    lr := lower(node.type)
    lr == "package"
    has_external_source_indicator(node)
}

has_external_source_indicator(node) {
    [_, n] := walk(node)
    n.ir_type == "Attribute"
    lower(n.name) in {"source", "provider"}
    [_, v] := walk(n.value)
    v.ir_type == "String"
    contains(lower(v.value), "http")
}

has_disabled_gpgcheck(node) {
    [_, n] := walk(node)
    n.ir_type == "Hash"
    some kv in n.value
    kv.key.ir_type == "String"
    lower(kv.key.value) in gpgcheck_keys
    is_disabled_value(kv.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    some node in glitch_lib.all_atomic_units(parent)
    is_external_download_resource(node)
    not has_integrity_attribute(node)
    not has_checksum_in_hash(node)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Remote file download without integrity verification - Resource downloads external content without checksum or signature validation. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    some node in glitch_lib.all_atomic_units(parent)
    attrs := glitch_lib.all_attributes(node)
    some attr in attrs
    lower(attr.name) in download_indicators
    any_string_has_insecure_protocol(attr.value)
    not has_integrity_attribute(node)
    not has_checksum_in_hash(node)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Insecure protocol download without integrity verification - HTTP/FTP used without checksum or signature validation. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    some node in glitch_lib.all_atomic_units(parent)
    attrs := glitch_lib.all_attributes(node)
    some attr in attrs
    lower(attr.name) in image_indicators
    any_string_has_floating_tag(attr.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Container image without immutable reference - Using floating tag instead of digest-based reference. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    [_, hash_node] := walk(parent)
    hash_node.ir_type == "Hash"
    some kv in hash_node.value
    kv.key.ir_type == "String"
    lower(kv.key.value) in gpgcheck_keys
    is_disabled_value(kv.value)
    result := {
        "type": "sec_no_int_check",
        "element": kv,
        "path": parent.path,
        "description": "GPG check disabled in repository configuration - Package signature verification disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    some node in glitch_lib.all_atomic_units(parent)
    attrs := glitch_lib.all_attributes(node)
    some attr in attrs
    lower(attr.name) in bypass_flags
    is_disabled_value(attr.value)
    lower(attr.name) != "validate_certs"
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Integrity verification explicitly disabled - Security check bypassed for package or data verification. (CWE-353)"
    }
}