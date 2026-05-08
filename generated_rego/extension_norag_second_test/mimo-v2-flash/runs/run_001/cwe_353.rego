package glitch

import data.glitch_lib

# Define attribute sets for detection
integrity_disabled_attrs := {
    "gpgcheck", "validate_certs", "signature", "verify", "integrity", "mac",
    "signature_required", "enforce_checksum", "validate_log_integrity", "source_verification",
    "payload_validation", "verify_signature", "checksum_header", "require_signature",
    "enforce_mac", "message_validation", "allow_unsigned_data", "bypass_integrity_check",
    "repo_gpgcheck", "enable_md5_check", "verify_checksum", "data_integrity_validation",
    "transfer_validation", "integrity_check", "signature_verification", "enable_data_integrity",
    "optional_checksum"
}

protocol_attrs := {"http", "udp"}

crypto_key_attrs := {
    "signing_key", "mac_key", "signature_key", "hmac_key"
}

required_signature_attrs := {
    "require_signature", "enforce_mac", "signature_required"
}

unsigned_data_attrs := {"allow_unsigned_data", "bypass_integrity_check"}

# Helper function to traverse to key-value nodes
traverse_to_key_values(node) = {n |
    walk(node, [path, n])
    n.ir_type == "Attribute"
} | {n |
    walk(node, [path, n])
    n.ir_type == "Variable"
}

# Helper function to check if a value is disabled
is_disabled(value) {
    value.ir_type == "Boolean"
    value.value == false
} else {
    value.ir_type == "String"
    regex.match("(?i)^(false|no|off|disabled|0)$", value.value)
} else {
    value.ir_type == "Integer"
    value.value == 0
}

# Helper function to check if a value is enabled
is_enabled(value) {
    value.ir_type == "Boolean"
    value.value == true
} else {
    value.ir_type == "String"
    regex.match("(?i)^(true|yes|on|enabled|1)$", value.value)
} else {
    value.ir_type == "Integer"
    value.value == 1
}

# Helper function to check if a protocol is insecure
is_unreliable_protocol(value) {
    value.ir_type == "String"
    lower(value.value) == "http" or lower(value.value) == "udp"
}

# Rule 1: Disabled integrity attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    variables := glitch_lib.all_variables(parent)
    nodes := atomic_units | variables
    node := nodes[_]
    attrs := traverse_to_key_values(node)
    
    some attr in attrs
    attr.name in integrity_disabled_attrs
    is_disabled(attr.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing support for integrity check - Configuration disables integrity validation"
    }
}

# Rule 2: Unreliable protocols without integrity
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    variables := glitch_lib.all_variables(parent)
    nodes := atomic_units | variables
    node := nodes[_]
    attrs := traverse_to_key_values(node)
    
    some attr in attrs
    (attr.name == "protocol" or attr.name == "transport")
    is_unreliable_protocol(attr.value)
    
    # Check that no integrity attributes are enabled
    no_integrity := true
    some integrity_attr in attrs
    integrity_attr.name in integrity_disabled_attrs
    is_enabled(integrity_attr.value)
    no_integrity := false
    
    no_integrity
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing support for integrity check - Using insecure transport without application-level integrity"
    }
}

# Rule 3: Required signature without signing keys
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    variables := glitch_lib.all_variables(parent)
    nodes := atomic_units | variables
    node := nodes[_]
    attrs := traverse_to_key_values(node)
    
    some attr in attrs
    attr.name in required_signature_attrs
    is_enabled(attr.value)
    
    # Check for absence of signing keys
    has_key := false
    some key_attr in attrs
    key_attr.name in crypto_key_attrs
    has_key := true
    
    not has_key
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing support for integrity check - Signature required but no signing keys configured"
    }
}

# Rule 4: Policies allowing unsigned data
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    variables := glitch_lib.all_variables(parent)
    nodes := atomic_units | variables
    node := nodes[_]
    attrs := traverse_to_key_values(node)
    
    some attr in attrs
    attr.name in unsigned_data_attrs
    is_enabled(attr.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing support for integrity check - Policy explicitly allows unsigned data or bypasses integrity"
    }
}