package glitch

import data.glitch_lib

integrity_disable_attrs := {
    "gpgcheck", "repo_gpgcheck", "gpg_verify", "validate_certs",
    "ssl_verify", "docker_content_trust", "content_trust"
}

integrity_skip_attrs := {
    "disable_gpg_check", "insecure_skip_verify", "tls_skip_verify",
    "skip_checksum", "ignore_checksum"
}

download_resource_types := {"remote_file", "archive", "get_url", "unarchive"}

checksum_attr_names := {"checksum", "sha256", "sha512", "md5", "hash", "integrity"}

is_falsy(value) {
    value.ir_type == "Boolean"
    value.value == false
}

is_falsy(value) {
    value.ir_type == "Integer"
    value.value == 0
}

is_falsy(value) {
    value.ir_type == "String"
    lower(value.value) == {"false", "no", "disabled", "0", "none"}[_]
}

is_truthy(value) {
    value.ir_type == "Boolean"
    value.value == true
}

is_truthy(value) {
    value.ir_type == "String"
    lower(value.value) == {"true", "yes"}[_]
}

has_checksum_attr(attrs) {
    attr := attrs[_]
    lower(attr.name) == checksum_attr_names[_]
}

Glitch_Analysis[result] {
    walk(input, [_, parent])
    parent.ir_type == "UnitBlock"
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "AtomicUnit"
    attr := node.attributes[_]
    lower(attr.name) == integrity_disable_attrs[_]
    is_falsy(attr.value)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing support for integrity check - Integrity verification is disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    walk(input, [_, parent])
    parent.ir_type == "UnitBlock"
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "AtomicUnit"
    attr := node.attributes[_]
    lower(attr.name) == integrity_skip_attrs[_]
    is_truthy(attr.value)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing support for integrity check - Integrity check is explicitly skipped. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    walk(input, [_, parent])
    parent.ir_type == "UnitBlock"
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "AtomicUnit"
    lower(node.type) == download_resource_types[_]
    not has_checksum_attr(node.attributes)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing support for integrity check - Download resource without checksum verification. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    walk(input, [_, parent])
    parent.ir_type == "UnitBlock"
    parent.path != ""
    walk(parent, [_, entry])
    is_object(entry)
    not entry.ir_type
    entry.key.ir_type == "String"
    lower(entry.key.value) == integrity_disable_attrs[_]
    is_falsy(entry.value)
    result := {
        "type": "sec_no_int_check",
        "element": entry.value,
        "path": parent.path,
        "description": "Missing support for integrity check - Integrity verification disabled in configuration. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    walk(input, [_, parent])
    parent.ir_type == "UnitBlock"
    parent.path != ""
    walk(parent, [_, entry])
    is_object(entry)
    not entry.ir_type
    entry.key.ir_type == "String"
    lower(entry.key.value) == integrity_skip_attrs[_]
    is_truthy(entry.value)
    result := {
        "type": "sec_no_int_check",
        "element": entry.value,
        "path": parent.path,
        "description": "Missing support for integrity check - Integrity check skipped in configuration. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    walk(input, [_, parent])
    parent.ir_type == "UnitBlock"
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "AtomicUnit"
    regex.match("(?si).*(source|url|src)\\s*(=>|[:=])?\\s*[\"']?http://.*", node.code)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing support for integrity check - Insecure HTTP URL used as resource source. (CWE-353)"
    }
}