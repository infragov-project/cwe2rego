package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Detect missing integrity checks in network transmissions
    # Check for clear-text protocols or missing TLS/SSL configuration
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for protocol attributes indicating unencrypted transmission
    lower_name := lower(attr.name)
    (lower_name == "protocol" or lower_name == "url" or lower_name == "source") and
    attr.value.ir_type == "String" and
    (
        regex.match("(?i)^(http://|ftp://|telnet://)", attr.value.value) or
        regex.match("(?i)^http[^s]", attr.value.value)
    )

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Unencrypted or unverified network transmission detected. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Detect missing integrity checks in data storage operations
    # Check for checksum_algorithm or signature attributes set to none/unsigned
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    lower_name := lower(attr.name)
    (lower_name == "checksum_algorithm" or lower_name == "signature" or lower_name == "validate_certs") and
    (
        (attr.value.ir_type == "String" and 
         (attr.value.value == "none" or attr.value.value == "unsigned" or 
          attr.value.value == "no" or attr.value.value == "false")) or
        (attr.value.ir_type == "Integer" and attr.value.value == 0)
    )

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Data transfer without validation detected. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Detect missing integrity checks in repository configurations
    # Check for gpgcheck or similar attributes set to 0/false
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    lower_name := lower(attr.name)
    (lower_name == "gpgcheck" or lower_name == "repo_gpgcheck" or 
     lower_name == "sslverify" or lower_name == "verify_tls") and
    (
        (attr.value.ir_type == "Integer" and attr.value.value == 0) or
        (attr.value.ir_type == "String" and 
         (attr.value.value == "no" or attr.value.value == "false"))
    )

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Repository without integrity verification detected. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Detect missing integrity checks in file operations (Chef remote_file)
    # Check for source URLs without HTTPS or missing validation
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    lower_name := lower(attr.name)
    lower_name == "source" and
    attr.value.ir_type == "String" and
    regex.match("(?i)^http://", attr.value.value)

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - File downloaded from unencrypted source. (CWE-353)"
    }
}