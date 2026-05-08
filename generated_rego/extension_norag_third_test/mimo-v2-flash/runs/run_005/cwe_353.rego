package glitch

import data.glitch_lib

# Detects CWE-353 (Missing Support for Integrity Check)
# by identifying insecure protocols (http) and disabled integrity checks.

# Attributes that explicitly disable integrity checks (e.g., "validate_certs: no")
insecure_flags := {"validate_certs", "ssl", "tls", "gpgcheck", "repo_gpgcheck", "https"}

# Helper: Check if a value represents a "disabled" security state
is_insecure_value(value) {
    value.ir_type == "Boolean"
    value.value == false
} else {
    value.ir_type == "String"
    lower(value.value) in {"no", "false", "disabled", "none"}
}

# Helper: Check if a string value starts with "http://" (insecure protocol)
is_insecure_url_protocol(value) {
    value.ir_type == "String"
    regex.match("^http://", lower(value.value))
}

# Helper: Recursively search Hash or Array for insecure URLs
check_complex_for_insecure_url(value) {
    value.ir_type == "Hash"
    walk(value, [path, node])
    node.ir_type == "String"
    regex.match("^http://", lower(node.value))
} else {
    value.ir_type == "Array"
    walk(value, [path, node])
    node.ir_type == "String"
    regex.match("^http://", lower(node.value))
}

# 1. Detect insecure flags (e.g., validate_certs: no)
# Covers Ansible, Chef, Puppet attributes/variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables and attributes in the parent block
    all_kvs := array.concat(glitch_lib.all_variables(parent), glitch_lib.all_attributes(parent))
    kv := all_kvs[_]
    
    # Match security control attributes
    insecure_flags[_] == lower(kv.name)
    
    # Match disabled values
    is_insecure_value(kv.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": kv,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Security verification explicitly disabled (CWE-353)"
    }
}

# 2. Detect insecure flags in atomic units (resources/tasks)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Match security control attributes
    insecure_flags[_] == lower(attr.name)
    
    # Match disabled values
    is_insecure_value(attr.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Security verification explicitly disabled (CWE-353)"
    }
}

# 3. Detect insecure HTTP protocol in specific attributes (url, source, baseurl, mirrorlist)
# This avoids false positives on generic strings (e.g., comments or metadata)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Target attributes commonly used for endpoints/locations
    attr.name in {"url", "source", "baseurl", "mirrorlist"}
    
    # Check for insecure protocol
    is_insecure_url_protocol(attr.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Insecure HTTP protocol used (CWE-353)"
    }
}

# 4. Detect insecure HTTP protocol in variables (Ansible vars, Chef attributes)
# This specifically targets variables holding URLs, avoiding false positives on unrelated strings
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Check if the variable name suggests it holds a URL (heuristic)
    url_name_pattern := "url|baseurl|mirrorlist|source"
    regex.match(url_name_pattern, lower(var.name))
    
    # Check if value contains insecure protocol
    is_insecure_url_protocol(var.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": var,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Variable uses insecure HTTP protocol (CWE-353)"
    }
}

# 5. Detect insecure HTTP protocol in nested structures (Hash/Array) within variables
# This handles cases like Ansible vars containing repo definitions with http URLs
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Check nested structures for insecure protocols
    check_complex_for_insecure_url(var.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": var,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Configuration contains insecure HTTP protocol (CWE-353)"
    }
}