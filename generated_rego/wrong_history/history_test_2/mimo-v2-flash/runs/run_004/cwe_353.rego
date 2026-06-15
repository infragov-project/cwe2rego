package glitch

import data.glitch_lib

import future.keywords.in

insecure_protocol_versions := {"tlsv1.0", "1.0", "ssl", "v1.0"}

integrity_attributes := {"checksum", "integrity", "digest", "validation_hash", "content_checksum"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name in {"ssl_version", "tls_version", "protocol_version"}
    attr.value.ir_type == "String"
    version := attr.value.value
    version in insecure_protocol_versions

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure protocol version configured - This may lack integrity checks. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    glitch_lib.traverse(node, "(?i).*file.*|.*transfer.*|.*object.*|.*storage.*")

    attrs := glitch_lib.all_attributes(node)
    
    not some attr in attrs; attr.name in integrity_attributes

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing integrity check in data transfer - No checksum or validation attributes found. (CWE-353)"
    }
}