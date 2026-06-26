package glitch

import data.glitch_lib

known_download_types := {"remote_file", "archive", "get_url", "wget", "download_file", "remote_zip", "http_request", "wget_package"}

url_source_types := {"package"}

integrity_pattern := "(?i)(checksum|sha256|sha512|sha384|sha224|sha1|md5|hash|integrity|verify_checksum)"

url_pattern := "(?i)(https?://|ftp://)"

has_integrity_attr(node) {
    walk(node, [_, attr])
    attr.ir_type == "Attribute"
    regex.match(integrity_pattern, attr.name)
}

Glitch_Analysis[result] {
    walk(input, [_, ub])
    ub.ir_type == "UnitBlock"
    ub.path != ""
    walk(ub, [_, node])
    node.ir_type == "AtomicUnit"
    node.type == known_download_types[_]
    not has_integrity_attr(node)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": ub.path,
        "description": "Missing Support for Integrity Check - Download resource without integrity verification. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    walk(input, [_, ub])
    ub.ir_type == "UnitBlock"
    ub.path != ""
    walk(ub, [_, node])
    node.ir_type == "AtomicUnit"
    node.type == url_source_types[_]
    not has_integrity_attr(node)
    regex.match(url_pattern, node.code)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": ub.path,
        "description": "Missing Support for Integrity Check - Package resource downloading from URL without integrity verification. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    walk(input, [_, ub])
    ub.ir_type == "UnitBlock"
    ub.path != ""
    walk(ub, [_, node])
    node.ir_type == "AtomicUnit"
    attr := node.attributes[_]
    lower(attr.name) == "gpgcheck"
    attr.value.ir_type == "Integer"
    attr.value.value == 0
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": ub.path,
        "description": "Missing Support for Integrity Check - GPG check is disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    walk(input, [_, ub])
    ub.ir_type == "UnitBlock"
    ub.path != ""
    walk(ub, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    lower(entry.key.value) == "gpgcheck"
    entry.value.ir_type == "Integer"
    entry.value.value == 0
    result := {
        "type": "sec_no_int_check",
        "element": entry.value,
        "path": ub.path,
        "description": "Missing Support for Integrity Check - GPG check is disabled in repository configuration. (CWE-353)"
    }
}