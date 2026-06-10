package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Pattern 1: Unencrypted Protocol Definitions
    (attr.name == "protocol" and attr.value.ir_type == "String" and attr.value.value == "HTTP") or
    (attr.name == "enable_https" and attr.value.ir_type == "Boolean" and attr.value.value == false) or
    (attr.name == "force_https" and attr.value.ir_type == "Boolean" and attr.value.value == false) or
    (attr.name == "https_only" and attr.value.ir_type == "Boolean" and attr.value.value == false) or
    
    # Pattern 2: Insecure Encryption Settings
    (attr.name == "ssl_enforcement_enabled" and attr.value.ir_type == "Boolean" and attr.value.value == false) or
    (attr.name == "encryption_in_transit" and attr.value.ir_type == "Boolean" and attr.value.value == false) or
    (attr.name == "tls_version" and attr.value.ir_type == "String" and (attr.value.value == "TLS1_0" or attr.value.value == "TLS1_1")) or
    
    # Pattern 3: Publicly Accessible Endpoints
    (attr.name == "public_network_access_enabled" and attr.value.ir_type == "Boolean" and attr.value.value == true) or
    (attr.name == "allow_blob_public_access" and attr.value.ir_type == "Boolean" and attr.value.value == true) or
    
    # Pattern 4: Connection Strings with Plaintext Credentials
    (attr.name == "connection_string" and attr.value.ir_type == "String" and regex.match(".*http://.*", attr.value.value)) or
    (attr.name == "connection_string" and attr.value.ir_type == "String" and regex.match(".*ftp://.*", attr.value.value)) or
    
    # Pattern 5: API or Service Endpoints Without HTTPS
    (attr.name == "endpoint" and attr.value.ir_type == "String" and regex.match("^http://.*", attr.value.value)) or
    
    # Pattern 6: Legacy/Deprecated Protocols Enabled
    (attr.name == "enable_legacy_protocols" and attr.value.ir_type == "Boolean" and attr.value.value == true) or
    
    # Pattern 7: Database or Storage Configurations
    (attr.name == "ssl_mode" and attr.value.ir_type == "String" and attr.value.value == "DISABLED") or
    (attr.name == "verify_certificate" and attr.value.ir_type == "Boolean" and attr.value.value == false)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - The IaC script configures a resource to use an unencrypted protocol or insecure encryption setting. (CWE-319)"
    }
}