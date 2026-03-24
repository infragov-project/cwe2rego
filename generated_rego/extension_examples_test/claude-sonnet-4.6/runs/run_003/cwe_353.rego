package glitch

import data.glitch_lib

download_types := {"get_url", "remote_file", "wget_if_missing", "ark", "remote_directory", "maven_artifact", "archive"}

integrity_attr_names := {"checksum", "source_hash", "sha256", "sha512", "md5sum", "hash", "artifact_hash", "source_code_hash", "signature"}

skip_verify_names := {"skip_verify", "insecure", "no_checksum", "no_verify", "skip_integrity_check"}

is_falsy(v) {
    v.ir_type == "Boolean"
    v.value == false
}

is_falsy(v) {
    v.ir_type == "Integer"
    v.value == 0
}

is_falsy(v) {
    v.ir_type == "String"
    lower(v.value) == {"no", "false", "off", "0"}[_]
}

is_truthy(v) {
    v.ir_type == "Boolean"
    v.value == true
}

is_truthy(v) {
    v.ir_type == "String"
    lower(v.value) == {"yes", "true", "on", "1"}[_]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    download_types[node.type]
    node_attrs := glitch_lib.all_attributes(node)
    attr_names := {a.name | a := node_attrs[_]}
    count({"url", "source"} & attr_names) > 0
    count(integrity_attr_names & attr_names) == 0
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Download resource without integrity verification - Missing checksum or hash attribute. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    not download_types[node.type]
    node_attrs := glitch_lib.all_attributes(node)
    attr_names := {a.name | a := node_attrs[_]}
    count(integrity_attr_names & attr_names) == 0
    attr := node_attrs[_]
    attr.name == "source"
    attr.value.ir_type == "String"
    regex.match("(?i)^(https?|ftp)://", attr.value.value)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Resource downloads from URL without integrity verification. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == "gpgcheck"
    is_falsy(attr.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "GPG check disabled - Package integrity cannot be verified. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, entry])
    entry.key.ir_type == "String"
    lower(entry.key.value) == "gpgcheck"
    is_falsy(entry.value)
    result := {
        "type": "sec_no_int_check",
        "element": entry.key,
        "path": parent.path,
        "description": "GPG check disabled in repository configuration. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == skip_verify_names[_]
    is_truthy(attr.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Integrity verification explicitly bypassed. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "image"
    attr.value.ir_type == "String"
    not contains(attr.value.value, "@sha256:")
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Container image without digest pinning - Use @sha256 digest. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "checksum_algorithm"
    attr.value.ir_type == "String"
    upper(attr.value.value) == "NONE"
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Checksum algorithm set to NONE. (CWE-353)"
    }
}