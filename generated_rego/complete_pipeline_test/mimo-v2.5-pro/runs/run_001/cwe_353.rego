package glitch

import data.glitch_lib

integrity_keywords := {
    "integrity", "checksum", "verification", "hmac", "signature", "signing",
    "unsigned", "message_authentication", "enable_integrity",
    "integrity_protection", "data_integrity", "require_signing",
    "checksum_type", "allow_unsigned", "skip_integrity_check",
    "disable_checksum", "enforce_integrity", "gpgcheck",
    "checksum_validation", "verify_signature", "check_signature"
}

download_resources := {"remote_file", "archive", "get_url", "http_request", "compressed_app", "package", "pip", "npm", "bower", "bower_package", "npm_package", "pip_package", "pip3", "maven_artifact"}

disablement_values := {"false", "disabled", "none", "no", "0", "off"}

is_disabled_pattern(value) {
    value.ir_type == "Boolean"
    not value.value
} else {
    value.ir_type == "String"
    disablement_values[lower(value.value)]
} else {
    value.ir_type == "Integer"
    value.value == 0
}

has_integrity_keyword(name) {
    lower_name := lower(name)
    keyword := integrity_keywords[_]
    contains(lower_name, keyword)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    has_integrity_keyword(entry.key.value)
    is_disabled_pattern(entry.value)
    glitch_lib.traverse_var(entry.value)
    result := {
        "type": "sec_no_int_check",
        "element": entry.key,
        "path": parent.path,
        "description": "Missing or disabled integrity check - Ensure integrity verification mechanisms are enabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    has_integrity_keyword(var.name)
    is_disabled_pattern(var.value)
    glitch_lib.traverse_var(var.value)
    result := {
        "type": "sec_no_int_check",
        "element": var,
        "path": parent.path,
        "description": "Missing or disabled integrity check - Ensure integrity verification mechanisms are enabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == download_resources[_]
    node.code != ""
    has_http_source_in_code(node)
    not has_checksum_in_code(node)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing integrity check - Download resource uses insecure HTTP source without checksum verification. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == download_resources[_]
    node.code != ""
    has_source_in_code(node)
    not has_checksum_in_code(node)
    not has_http_source_in_code(node)
    not has_https_source_in_code(node)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing integrity check - Download resource without checksum verification. (CWE-353)"
    }
}

has_http_source_in_code(node) {
    regex.match(`(?i)\b(?:source|url)\s*[=:>]+\s*['"]?http://`, node.code)
}

has_https_source_in_code(node) {
    regex.match(`(?i)\b(?:source|url)\s*[=:>]+\s*['"]?https://`, node.code)
}

has_source_in_code(node) {
    regex.match(`(?i)\b(?:source|url)\s*[=:]`, node.code)
} else {
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    lower(attr.name) == "source"
} else {
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    lower(attr.name) == "url"
}

has_checksum_in_code(node) {
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    regex.match(`(?i)checksum|sha256|sha1|md5|digest|integrity`, lower(attr.name))
} else {
    regex.match(`(?i)\bchecksum\b`, node.code)
}