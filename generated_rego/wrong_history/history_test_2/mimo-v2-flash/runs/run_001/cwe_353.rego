package glitch

import data.glitch_lib

data_handling_attrs := {"source", "destination", "url", "script", "user_data", "file", "content"}
integrity_attrs := {"checksum", "hash", "md5", "sha256", "validation", "integrity", "enable_integrity_check", "versioning", "immutable", "verify", "signature", "gpg", "pgp", "trusted_cert"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    data_attr := attrs[_]
    data_attr.name == data_handling_attrs[_]

    not has_integrity_attribute(attrs)

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing integrity check in data transfer or storage operation. (CWE-353)"
    }
}

has_integrity_attribute(attrs) {
    attr := attrs[_]
    attr.name == integrity_attrs[_]
}