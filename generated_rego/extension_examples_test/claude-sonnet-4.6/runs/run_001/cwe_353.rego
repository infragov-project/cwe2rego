package glitch

import data.glitch_lib

gpg_check_names := {"gpgcheck", "gpg_check", "repo_gpgcheck", "verify_signature", "signature_check"}

download_attr_names := {"url", "source", "src"}

integrity_check_attrs := {"checksum", "sha256", "sha512", "md5", "source_hash", "hash", "verify_checksum"}

mutable_branch_names := {"main", "master", "develop", "dev", "latest"}

is_false_value(v) {
    v.ir_type == "Boolean"
    v.value == false
}

is_false_value(v) {
    v.ir_type == "String"
    lower(v.value) == "false"
}

is_false_value(v) {
    v.ir_type == "String"
    lower(v.value) == "no"
}

is_false_value(v) {
    v.ir_type == "Integer"
    v.value == 0
}

is_empty_or_none(v) {
    v.ir_type == "String"
    lower(v.value) == "none"
}

is_empty_or_none(v) {
    v.ir_type == "String"
    v.value == ""
}

is_empty_or_none(v) {
    v.ir_type == "Null"
}

source_likely_remote(v) {
    v.ir_type == "String"
    not regex.match("^/", v.value)
    regex.match("://", v.value)
}

source_likely_remote(v) {
    v.ir_type == "Sum"
}

source_likely_remote(v) {
    v.ir_type == "MethodCall"
}

source_likely_remote(v) {
    v.ir_type == "VariableReference"
}

source_likely_remote(v) {
    v.ir_type == "FunctionCall"
}

has_integrity_check(node) {
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    integrity_check_attrs[attr.name]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    gpg_check_names[attr.name]
    is_false_value(attr.value)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing integrity check - GPG/signature verification disabled in resource. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_entry])
    hash_entry.key.ir_type == "String"
    gpg_check_names[lower(hash_entry.key.value)]
    is_false_value(hash_entry.value)
    result := {
        "type": "sec_no_int_check",
        "element": hash_entry.key,
        "path": parent.path,
        "description": "Missing integrity check - GPG check disabled in nested repository or variable configuration. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    download_attr_names[attr.name]
    source_likely_remote(attr.value)
    not has_integrity_check(node)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing integrity check - Remote resource fetched without integrity verification. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "insecure_skip_verify"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing integrity check - insecure_skip_verify is enabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "image"
    attr.value.ir_type == "String"
    not regex.match(".*@sha256:[a-f0-9]+.*", attr.value.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing integrity check - Container image uses mutable tag without content digest. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    integrity_check_attrs[attr.name]
    is_empty_or_none(attr.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing integrity check - Checksum or hash field is empty or set to none. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "ref"
    attr.value.ir_type == "String"
    mutable_branch_names[attr.value.value]
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing integrity check - Module ref points to a mutable branch name. (CWE-353)"
    }
}