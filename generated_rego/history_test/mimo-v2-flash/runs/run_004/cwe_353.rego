package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name in {"protocol", "ssl_mode", "ssl_policy", "encryption", "tls"}
    
    attr.value.ir_type == "String"
    (attr.value.value == "http" || attr.value.value == "ftp" || attr.value.value == "telnet")
    
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Insecure protocol configuration detected. Use HTTPS or TLS-enabled protocols. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name in {"enable_tls", "tls_disabled", "ssl_certificate"}
    
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - TLS/SSL explicitly disabled. Enable TLS to ensure data integrity. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name in {"checksum_algorithm", "integrity_check", "validate_checksum"}
    
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Integrity validation explicitly disabled. Enable checksums or integrity checks. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name in {"checksum_algorithm", "integrity_check"}
    attr.value.ir_type == "String"
    attr.value.value == ""
    
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Checksum algorithm or integrity check field is empty. Define a checksum algorithm (e.g., SHA-256). (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "ssl_mode"
    attr.value.ir_type == "String"
    (attr.value.value == "disabled" || attr.value.value == "none")
    
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - SSL mode disabled or set to none. Enable TLS/SSL to ensure data integrity. (CWE-353)"
    }
}