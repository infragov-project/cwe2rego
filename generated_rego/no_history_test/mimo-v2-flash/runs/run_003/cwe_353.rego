package glitch

import data.glitch_lib

insecure_protocols = ["HTTP", "FTP", "Telnet", "SMTP", "plaintext", "unencrypted", "insecure"]
integrity_attributes = {"integrity_checks", "checksum_validation", "hash_verification", "enable_checksum", "require_data_integrity", "gpgcheck"}
encryption_attributes = {"encryption", "ssl_version", "tls_disabled", "https_only", "require_tls"}
public_access_attributes = {"public_read", "public_access", "allow_http"}
protocol_attributes = {"protocol", "protocol_type", "transport_protocol"}
checksum_attributes = {"checksum_algorithm", "hash", "signature", "digest"}
data_transmission_attributes = {"source", "url", "protocol"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    protocol_attributes[attr.name]
    attr.value.ir_type == "String"
    regex.match(sprintf("(?i)^(%s)$", [concat("|", insecure_protocols)]), attr.value.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure protocol usage without integrity checks - Protocol lacks built-in integrity verification (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, n])
    n.ir_type == "Attribute"
    integrity_attributes[n.name]
    invalid_integrity_value(n.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": n,
        "path": parent.path,
        "description": "Integrity checks explicitly disabled - Data transmission lacks integrity verification (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, hash_node])
    hash_node.ir_type == "Hash"
    key_value := hash_node.value[_]
    key_value.key.ir_type == "String"
    integrity_attributes[key_value.key.value]
    invalid_integrity_value(key_value.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": key_value.key,
        "path": parent.path,
        "description": "Integrity checks explicitly disabled - Data transmission lacks integrity verification (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    data_transmission_attributes[attr.name]
    
    not has_integrity_checks(node)
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Insecure data transmission without integrity checks - Missing checksum or encryption (CWE-353)"
    }
}

invalid_integrity_value(value) {
    value.ir_type == "Boolean"
    value.value == false
}

invalid_integrity_value(value) {
    value.ir_type == "Integer"
    value.value == 0
}

has_integrity_checks(node) {
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    integrity_attributes[attr.name]
    attr.value.ir_type == "Boolean"
    attr.value.value == true
}

has_integrity_checks(node) {
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    encryption_attributes[attr.name]
    attr.value.ir_type == "String"
    regex.match("(?i)^(enabled|true|1\\.2|1\\.3)$", attr.value.value)
}