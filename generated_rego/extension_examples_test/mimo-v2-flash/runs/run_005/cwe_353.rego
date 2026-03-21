package glitch

import data.glitch_lib
import future.keywords.in

insecure_protocols := {"http", "udp", "custom"}
integrity_attributes := {"checksum", "integrity_validation", "hash", "signature"}
disablement_names := {"disable_checksum", "no_integrity_check"}
insecure_source_patterns := {"^http://", "^udp://", "^custom://"}

check_protocol_insecure(protocol_value) {
    protocol_value.ir_type == "String"
    regex.match("(?i)^(http|udp|custom)$", protocol_value.value)
}

check_url_insecure(url_value) {
    url_value.ir_type == "String"
    regex.match("(?i)^(http://|udp://|custom://)", url_value.value)
}

has_integrity_attributes(attrs) {
    some attr in attrs
    integrity_attributes[attr.name]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    
    protocol_attr := attrs[_]
    protocol_attr.name == "protocol"
    check_protocol_insecure(protocol_attr.value)
    
    not has_integrity_attributes(attrs)
    
    result := {
        "type": "sec_no_int_check",
        "element": protocol_attr,
        "path": parent.path,
        "description": "Missing integrity checks in transmission protocol - Protocols like HTTP, UDP should have integrity checks enabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    
    disable_attr := attrs[_]
    disable_attr.name in disablement_names
    disable_attr.value.ir_type == "Boolean"
    disable_attr.value.value == true
    
    result := {
        "type": "sec_no_int_check",
        "element": disable_attr,
        "path": parent.path,
        "description": "Integrity checks explicitly disabled - This can lead to data corruption or tampering. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    
    source_attr := attrs[_]
    source_attr.name == "source"
    check_url_insecure(source_attr.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": source_attr,
        "path": parent.path,
        "description": "Insecure source URL - Using HTTP or other insecure protocol for source. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    
    validate_certs_attr := attrs[_]
    validate_certs_attr.name == "validate_certs"
    validate_certs_attr.value.ir_type == "String"
    validate_certs_attr.value.value == "no"
    
    result := {
        "type": "sec_no_int_check",
        "element": validate_certs_attr,
        "path": parent.path,
        "description": "Certificate validation disabled - This allows insecure connections without integrity checks. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    
    gpgcheck_attr := attrs[_]
    gpgcheck_attr.name == "gpgcheck"
    gpgcheck_attr.value.ir_type == "Integer"
    gpgcheck_attr.value.value == 0
    
    result := {
        "type": "sec_no_int_check",
        "element": gpgcheck_attr,
        "path": parent.path,
        "description": "GPG signature checking disabled - Packages are not verified for integrity. (CWE-353)"
    }
}