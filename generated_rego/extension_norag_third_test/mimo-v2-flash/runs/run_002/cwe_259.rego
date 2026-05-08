Based on the requirements and the provided examples, here's the Rego rule to detect CWE-259 (Hard-coded Passwords) across Ansible, Chef, and Puppet IaC technologies:

```rego
package glitch

import data.glitch_lib

password_keywords := {"password", "pwd", "pass", "secret", "token", "credential", "api_key", "access_key", "secret_key", "admin_password", "master_password"}

is_sensitive_name(name) {
    some keyword
    password_keywords[keyword]
    regex.match(sprintf("(?i).*%s.*", [keyword]), name)
}

is_hardcoded_string(value) {
    value.ir_type == "String"
    value.value != ""
    not is_dynamic_reference(value)
}

is_dynamic_reference(value) {
    value.ir_type == "VariableReference"
} else {
    value.ir_type == "FunctionCall"
} else {
    value.ir_type == "MethodCall"
} else {
    regex.match(".*\\$\\{.*", value.value)
} else {
    startswith(value.value, "var.")
} else {
    startswith(value.value, "data.")
} else {
    startswith(value.value, "secrets.")
} else {
    startswith(value.value, "lookup(")
} else {
    startswith(value.value, "env[")
}

check_sensitive_in_hash(hash) {
    hash.ir_type == "Hash"
    pair := hash.value[_]
    key := pair.key
    value := pair.value
    key.ir_type == "String"
    is_sensitive_name(key.value)
    is_hardcoded_string(value)
}

check_sensitive_in_array(array) {
    array.ir_type == "Array"
    element := array.value[_]
    element.ir_type == "String"
    regex.match(`(?i)(password|pwd|pass|secret|token|credential|api_key|access_key|secret_key|admin_password|master_password)=.+`, element.value)
}

# Rule 1: Top-level attributes with sensitive names and hard-coded strings
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_sensitive_name(attr.name)
    is_hardcoded_string(attr.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid using hard-coded passwords or credentials. (CWE-259)"
    }
}

# Rule 2: Top-level variables with sensitive names and hard-coded strings
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_sensitive_name(var.name)
    is_hardcoded_string(var.value)
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid using hard-coded passwords or credentials. (CWE-259)"
    }
}

# Rule 3: Attributes containing hashes with sensitive keys and hard-coded values
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    check_sensitive_in_hash(attr.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid using hard-coded passwords or credentials. (CWE-259)"
    }
}

# Rule 4: Variables containing hashes with sensitive keys and hard-coded values
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    check_sensitive_in_hash(var.value)
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid using hard-coded passwords or credentials. (CWE-259)"
    }
}

# Rule 5: Attributes containing arrays with sensitive patterns
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "Array"
    check_sensitive_in_array(attr.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid using hard-coded passwords or credentials. (CWE-259)"
    }
}

# Rule 6: Variables containing arrays with sensitive patterns
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "Array"
    check_sensitive_in_array(var.value)
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid using hard-coded passwords or credentials. (CWE-259)"
    }
}

# Rule 7: Attributes containing nested hashes with sensitive keys and hard-coded values
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "Hash"
    pair := attr.value.value[_]
    val := pair.value
    check_sensitive_in_hash(val)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid using hard-coded passwords or credentials. (CWE-259)"
    }
}

# Rule 8: Variables containing nested hashes with sensitive keys and hard-coded values
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "Hash"
    pair := var.value.value[_]
    val := pair.value
    check_sensitive_in_hash(val)
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid using hard-coded passwords or credentials. (CWE-259)"
    }
}

# Rule 9: Attributes containing arrays of hashes with sensitive keys and hard-coded values
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "Array"
    element := attr.value.value[_]
    element.ir_type == "Hash"
    pair := element.value[_]
    key := pair.key
    value := pair.value
    is_sensitive_name(key.value)
    is_hardcoded_string(value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid using hard-coded passwords or credentials. (CWE-259)"
    }
}

# Rule 10: Variables containing arrays of hashes with sensitive keys and hard-coded values
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "Array"
    element := var.value.value[_]
    element.ir_type == "Hash"
    pair := element.value[_]
    key := pair.key
    value := pair.value
    is_sensitive_name(key.value)
    is_hardcoded_string(value)
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid using hard-coded passwords or credentials. (CWE-259)"
    }
}
```

This rule:

1. **Detects hard-coded passwords** in attributes and variables across IaC technologies
2. **Handles multiple patterns**:
   - Direct string assignments
   - Nested hashes
   - Arrays with sensitive patterns
   - Nested structures (hashes within hashes, arrays within hashes)
3. **Avoids false positives** by excluding dynamic references
4. **Is technology-agnostic** (works for Ansible, Chef, Puppet)
5. **Covers all scenarios** from the provided examples:
   - Ansible: Hashes in arrays with sensitive keys
   - Puppet: Nested strings in environment variables
   - Complex nested structures in configuration data

The rule uses multiple patterns to detect hard-coded passwords while minimizing false positives by excluding dynamic references like variable substitutions, function calls, and known secret management patterns.