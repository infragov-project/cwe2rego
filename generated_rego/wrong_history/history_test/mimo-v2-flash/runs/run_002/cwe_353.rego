package glitch

import data.glitch_lib

vulnerable_protocols := {"tcp", "udp", "http", "ftp", "telnet"}
protocol_attributes := {"protocol", "transport", "encryption_algorithm", "mode"}
integrity_attributes := {"integrity_check", "checksum", "verify_integrity", "checksum_validation", "verify_data"}
disabled_integrity_values := {"false", "disabled", "none", "null"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)

    protocol_attr := attrs[_]
    protocol_attr.name in protocol_attributes
    protocol_attr.value.ir_type == "String"
    protocol_attr.value.value in vulnerable_protocols

    integrity_attrs := {attr | attr in attrs; attr.name in integrity_attributes}
    count(integrity_attrs) == 0

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - The IaC script configures a network protocol without enabling integrity validation. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)

    protocol_attr := attrs[_]
    protocol_attr.name in protocol_attributes
    protocol_attr.value.ir_type == "String"
    protocol_attr.value.value in vulnerable_protocols

    integrity_attr := attrs[_]
    integrity_attr.name in integrity_attributes
    integrity_attr.value.ir_type == "String"
    integrity_attr.value.value in disabled_integrity_values

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - The IaC script configures a network protocol with integrity validation disabled. (CWE-353)"
    }
}