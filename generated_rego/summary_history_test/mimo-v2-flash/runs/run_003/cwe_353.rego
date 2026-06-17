package glitch

import data.glitch_lib
import future.keywords.in

protocol_keywords := {"protocol", "transport", "endpoint", "uri", "url", "connection", "source"}
insecure_protocols := {"http", "ftp", "telnet", "smtp"}
tls_keywords := {"tls", "encryption", "ssl", "validate_certs"}
source_keywords := {"source", "url", "uri", "location"}
integrity_keywords := {"checksum", "hash", "signature", "verify", "integrity", "gpgcheck"}
package_keywords := {"package", "artifact", "version", "name"}

check_insecure_protocol(value) {
    value.ir_type == "String"
    regex.match("^(http|ftp|telnet|smtp)://", value.value)
} else {
    value.ir_type == "Sum"
    regex.match("^(http|ftp|telnet|smtp)://", value.code)
}

find_all_attributes_deep(node) = attrs {
    attrs := {attr |
        walk(node, [path, n])
        n.ir_type == "Attribute"
        attr := n
    }
}

find_hash_pairs_deep(node) = pairs {
    pairs := {pair |
        walk(node, [path, n])
        n.ir_type == "Hash"
        item := n.value[_]
        pair := {"name": item.key.value, "value": item.value}
    }
}

get_all_attributes_deep(node) = attrs {
    attrs := find_all_attributes_deep(node) | find_hash_pairs_deep(node)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    nodes := glitch_lib.all_atomic_units(parent) | glitch_lib.all_variables(parent)
    node := nodes[_]
    
    attrs := get_all_attributes_deep(node)
    protocol_attrs := {a | a := attrs[_]; protocol_keywords[a.name]}
    count(protocol_attrs) > 0
    
    attr := protocol_attrs[_]
    check_insecure_protocol(attr.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Use of insecure protocol without integrity checks. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    nodes := glitch_lib.all_atomic_units(parent) | glitch_lib.all_variables(parent)
    node := nodes[_]
    
    attrs := get_all_attributes_deep(node)
    tls_attrs := {a | a := attrs[_]; tls_keywords[a.name]}
    count(tls_attrs) > 0
    
    attr := tls_attrs[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "TLS or encryption disabled, missing integrity protection. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    nodes := glitch_lib.all_atomic_units(parent) | glitch_lib.all_variables(parent)
    node := nodes[_]
    
    attrs := get_all_attributes_deep(node)
    validate_certs_attrs := {a | a := attrs[_]; a.name == "validate_certs"}
    count(validate_certs_attrs) > 0
    
    attr := validate_certs_attrs[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Certificate validation disabled, missing integrity protection. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    pairs := find_hash_pairs_deep(parent)
    pair := pairs[_]
    pair.name == "gpgcheck"
    pair.value.ir_type == "Integer"
    pair.value.value == 0
    
    result := {
        "type": "sec_no_int_check",
        "element": pair.value,
        "path": parent.path,
        "description": "GPG check disabled in package repository, missing integrity protection. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    nodes := glitch_lib.all_atomic_units(parent) | glitch_lib.all_variables(parent)
    node := nodes[_]
    
    attrs := get_all_attributes_deep(node)
    source_attrs := {a | a := attrs[_]; source_keywords[a.name]}
    count(source_attrs) > 0
    
    integrity_attrs := {a | a := attrs[_]; integrity_keywords[a.name]}
    count(integrity_attrs) == 0
    
    source_attr := source_attrs[_]
    not check_insecure_protocol(source_attr.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing checksum or hash for data download. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    nodes := glitch_lib.all_atomic_units(parent)
    node := nodes[_]
    
    attrs := get_all_attributes_deep(node)
    package_attrs := {a | a := attrs[_]; package_keywords[a.name]}
    count(package_attrs) > 0
    
    signature_attrs := {a | a := attrs[_]; a.name == "signature"}
    count(signature_attrs) == 0
    
    package_attr := package_attrs[_]
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing digital signature for package or artifact. (CWE-353)"
    }
}

has_integrity_flag(call, flags) {
    call.ir_type == "FunctionCall"
    some arg in call.args
    arg.ir_type == "String"
    flags[arg.value]
} else {
    call.ir_type == "MethodCall"
    some arg in call.args
    arg.ir_type == "String"
    flags[arg.value]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    parent.type == "script"
    
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    node.name == "curl"
    not has_integrity_flag(node, {"--checksum", "--verify"})
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Script command 'curl' without integrity check flag. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    parent.type == "script"
    
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    node.name == "wget"
    not has_integrity_flag(node, {"--checksum"})
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Script command 'wget' without integrity check flag. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    parent.type == "script"
    
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    node.name == "apt-get"
    some arg in node.args
    arg.ir_type == "String"
    arg.value == "install"
    has_integrity_flag(node, {"--allow-unauthenticated"})
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Script command 'apt-get' with --allow-unauthenticated flag, disabling GPG check. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    parent.type == "script"
    
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    node.name == "yum"
    some arg in node.args
    arg.ir_type == "String"
    arg.value == "install"
    has_integrity_flag(node, {"--nogpgcheck"})
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Script command 'yum' with --nogpgcheck flag, disabling GPG check. (CWE-353)"
    }
}