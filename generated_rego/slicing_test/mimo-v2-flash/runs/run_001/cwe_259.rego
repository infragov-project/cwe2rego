package glitch

import data.glitch_lib

# Define keywords related to secrets/passwords
# We include "password", "secret", "credential", "auth", "token", "key"
# We also include specific patterns like "keystore" but will handle context later
password_patterns := {"password", "secret", "credential", "auth", "token", "key", "passwd"}

# Check if a key string matches any of the password patterns (case-insensitive)
is_password_key(key_str) {
    regex.match(sprintf("(?i)^(.*_)?(%s)(s|es)?(_.*|$)", [concat("|", password_patterns)]), key_str)
}

# Check if a value looks like a hardcoded secret (non-empty string)
# Excluding strings that look like variable references or function calls
is_hardcoded_secret(val) {
    val.ir_type == "String"
    count(val.value) > 0
    # Exclude common placeholders or weak patterns if needed, but for CWE-259,
    # any hardcoded string in a password field is a violation.
    # The prompt asks to avoid false positives like 'keystore' paths.
    # We will refine the key matching to be more specific.
}

# Specific refinement to avoid flagging 'keystore' as a password field
# 'keystore' is a path to a file, not a password itself.
is_password_key_refined(key_str) {
    is_password_key(key_str)
    not key_str == "keystore"
    not key_str == "keystores"
}

# Walk through complex structures (Hash/Array) to find key-value pairs
# where the key matches a password pattern and the value is a hardcoded string
find_password_violations(node) = violations {
    violations := {violation |
        walk(node, [path, n])
        n.ir_type == "Hash"
        pair := n.value[_]
        k := pair.key.value
        v := pair.value
        is_password_key_refined(k)
        is_hardcoded_secret(v)
        violation := {"key": k, "value": v, "path": path}
    }
}

# Rule for Variables: Check direct string values in password-keyed variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Check if the variable name itself indicates a password
    is_password_key_refined(var.name)
    var.value.ir_type == "String"
    is_hardcoded_secret(var.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Hard-coded passwords in IaC scripts pose a security risk. (CWE-259)"
    }
}

# Rule for Variables: Check nested structures (Hash/Array) for password keys with hardcoded strings
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    violations := find_password_violations(var.value)
    count(violations) > 0
    violation := violations[_]
    
    result := {
        "type": "sec_hard_pass",
        "element": violation.value,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Hard-coded passwords in IaC scripts pose a security risk. (CWE-259)"
    }
}

# Rule for Attributes: Check direct string values in password-keyed attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    is_password_key_refined(attr.name)
    attr.value.ir_type == "String"
    is_hardcoded_secret(attr.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Hard-coded passwords in IaC scripts pose a security risk. (CWE-259)"
    }
}

# Rule for Attributes: Check nested structures (Hash/Array) for password keys with hardcoded strings
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    violations := find_password_violations(attr.value)
    count(violations) > 0
    violation := violations[_]
    
    result := {
        "type": "sec_hard_pass",
        "element": violation.value,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Hard-coded passwords in IaC scripts pose a security risk. (CWE-259)"
    }
}

# Rule for Atomic Units: Check for password violations within atomic units
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    violations := find_password_violations(node)
    count(violations) > 0
    violation := violations[_]
    
    result := {
        "type": "sec_hard_pass",
        "element": violation.value,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Hard-coded passwords in IaC scripts pose a security risk. (CWE-259)"
    }
}