package glitch

import data.glitch_lib

# Attributes that disable integrity verification
integrity_disable_attrs := {"gpgcheck", "repo_gpgcheck", "pkg_gpgcheck", "validate_certs", "verify_ssl", "ssl_verify", "insecure_skip_verify", "ssl", "tls_enabled", "ssl_enabled", "verify_mode", "verify_peer", "verify_hostname", "skip_verify", "no_verify", "insecure", "trust_cert", "disable_checksum", "ignore_integrity", "skip_digest_check"}

# Values indicating disabled state
disabled_string_values := {"no", "false", "false", "0", "off"}

# Integrity verification attributes
integrity_attrs := {"checksum", "sha256", "digest", "md5", "signature", "verify_checksum", "checksum_algorithm", "hash_algorithm", "sha1", "sha256sum", "sha512", "signing_key", "gpg_key", "fingerprint", "gpg_key_url", "key_url"}

# Resource types that download external content
download_resource_types := {"get_url", "download", "fetch", "wget", "curl", "remote_file", "archive", "unarchive", "uri", "win_get_url", "package", "apt", "yum", "dnf", "zypper", "pacman", "pip", "gem", "npm", "docker_image"}

# Source URL attributes
source_attrs := {"source", "url", "src", "uri", "download_url", "baseurl", "mirrorlist"}

# Check if value is disabled
is_disabled_value(value) {
    value.ir_type == "String"
    lower(value.value) == disabled_string_values[_]
}

is_disabled_value(value) {
    value.ir_type == "Integer"
    value.value == 0
}

is_disabled_value(value) {
    value.ir_type == "Boolean"
    value.value == false
}

# Check if atomic unit has integrity verification
has_integrity_verification(node) {
    walk(node, [_, n])
    n.ir_type == "Attribute"
    integrity_attrs[lower(n.name)]
}

# Check for weak protocol in any string
has_weak_protocol(root) {
    walk(root, [_, n])
    n.ir_type == "String"
    contains(lower(n.value), "http://")
}

has_weak_protocol(root) {
    walk(root, [_, n])
    n.ir_type == "String"
    contains(lower(n.value), "ftp://")
}

# Find disabled integrity attributes anywhere in structure
find_disabled_integrity_match(root) = result {
    walk(root, [path, n])
    n.ir_type == "Hash"
    
    # Direct entries in this hash
    entry := n.value[_]
    entry.key.ir_type == "String"
    attr_name := lower(entry.key.value)
    integrity_disable_attrs[attr_name]
    is_disabled_value(entry.value)
    
    result := {
        "key": entry.key,
        "value": entry.value,
        "name": attr_name,
        "path": path
    }
}

# Detection: Disabled integrity attributes in any Value structure
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Walk all nodes to find disabled integrity settings
    walk(parent, [path, node])
    
    # Match in Hash entries
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    attr_name := lower(entry.key.value)
    integrity_disable_attrs[attr_name]
    is_disabled_value(entry.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": entry.value,
        "path": parent.path,
        "description": sprintf("Missing support for integrity check - Security verification '%s' disabled without alternative integrity mechanism. (CWE-353)", [attr_name])
    }
}

# Detection: Download resources without integrity verification and with disabled SSL
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "AtomicUnit"
    download_resource_types[lower(node.type)]
    
    not has_integrity_verification(node)
    
    walk(node, [_, attr])
    attr.ir_type == "Attribute"
    ssl_disable_attrs := {"validate_certs", "verify_ssl", "ssl_verify", "insecure_skip_verify", "ssl", "tls_enabled", "ssl_enabled", "verify_mode", "verify_peer", "verify_hostname", "skip_verify", "no_verify", "insecure"}
    ssl_disable_attrs[lower(attr.name)]
    is_disabled_value(attr.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing support for integrity check - SSL/TLS certificate validation disabled without integrity verification for downloaded resource. (CWE-353)"
    }
}

# Detection: Download resources using weak protocols without integrity verification
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "AtomicUnit"
    download_resource_types[lower(node.type)]
    
    not has_integrity_verification(node)
    
    walk(node, [_, attr])
    attr.ir_type == "Attribute"
    source_attrs[lower(attr.name)]
    has_weak_protocol(attr.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing support for integrity check - External resource retrieved over unencrypted channel without integrity verification. (CWE-353)"
    }
}

# Detection: Generic download resources without any integrity verification
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "AtomicUnit"
    download_resource_types[lower(node.type)]
    
    not has_integrity_verification(node)
    
    # Exclude if it has disabled SSL check
    not has_disabled_ssl_attr(node)
    
    # Exclude if it has weak protocol in source
    not has_weak_protocol_in_source_attr(node)
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing support for integrity check - External resource downloaded without integrity verification (no checksum, signature, or digest). (CWE-353)"
    }
}

has_disabled_ssl_attr(node) {
    walk(node, [_, attr])
    attr.ir_type == "Attribute"
    ssl_disable_attrs := {"validate_certs", "verify_ssl", "ssl_verify", "insecure_skip_verify", "ssl", "tls_enabled", "ssl_enabled", "verify_mode", "verify_peer", "verify_hostname", "skip_verify", "no_verify", "insecure"}
    ssl_disable_attrs[lower(attr.name)]
    is_disabled_value(attr.value)
}

has_weak_protocol_in_source_attr(node) {
    walk(node, [_, attr])
    attr.ir_type == "Attribute"
    source_attrs[lower(attr.name)]
    has_weak_protocol(attr.value)
}