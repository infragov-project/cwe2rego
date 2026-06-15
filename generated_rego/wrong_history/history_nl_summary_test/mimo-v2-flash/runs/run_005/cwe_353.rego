package glitch

import data.glitch_lib

# Set of insecure attribute names and their insecure values
insecure_attributes = {
    "validate_certs": {false, "no", "false", "0"},
    "gpgcheck": {0, "false", "no"},
    "signature_validation": {false, "disabled", "no"},
    "checksum_algorithm": {"none", "disabled"},
    "enable_checksum": {false, "no", "0"},
    "integrity_check": {false, "no", "0"},
    "force_https": {false, "no", "0"},
    "allow_insecure": {true, "yes", "1"},
    "ssl_disabled": {true, "yes", "1"},
    "public_access": {true, "yes", "1"},
    "encryption": {"none", "disabled", "false"}
}

# Helper function to check if a value is insecure
check_insecure_value(value, insecure_values) {
    value.ir_type == "Boolean"
    value.value == insecure_values[_]
} else {
    value.ir_type == "String"
    insecure_value := insecure_values[_]
    regex.match(sprintf("(?i)^%s$", [insecure_value]), value.value)
} else {
    value.ir_type == "Integer"
    insecure_value := insecure_values[_]
    value.value == insecure_value
}

# Rule for detecting insecure attributes in atomic units (Ansible, Chef, Puppet)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    insecure_values := insecure_attributes[attr.name]
    check_insecure_value(attr.value, insecure_values)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure configuration detected - Missing integrity check during data transmission (CWE-353)"
    }
}

# Rule for detecting insecure attributes in variables (hashes) - handles nested structures
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    walk(var.value, [path, node])
    node.ir_type == "Attribute"
    insecure_values := insecure_attributes[node.name]
    check_insecure_value(node.value, insecure_values)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Insecure configuration detected - Missing integrity check during data transmission (CWE-353)"
    }
}

# Rule for detecting HTTP URLs (insecure protocols) in any node
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.code != ""
    regex.match(`http://`, node.code)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Insecure HTTP URL detected - Missing integrity check during data transmission (CWE-353)"
    }
}

# Rule for detecting missing integrity checks in download resources (Chef remote_file, Puppet archive)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type in {"remote_file", "archive", "cookbook_file"}
    attrs := glitch_lib.all_attributes(node)
    # Check if source/url attribute exists (indicating download)
    has_source := any(attrs, a, a.name == "source" | a.name == "url")
    # Check if integrity check attributes are missing
    not has_integrity_attributes(attrs)
    has_source
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Insecure configuration detected - Missing integrity check during data transmission (CWE-353)"
    }
}

# Helper function to check if integrity attributes exist
has_integrity_attributes(attrs) {
    a := attrs[_]
    a.name in {"checksum", "verify", "validate", "signature", "integrity_check"}
}

# Rule for detecting insecure protocols in resource attributes (like cookie in Puppet archive)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name in {"cookie", "header", "source"}
    attr.value.ir_type == "String"
    regex.match(`http://`, attr.value.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure protocol in attribute detected - Missing integrity check during data transmission (CWE-353)"
    }
}