package glitch

import data.glitch_lib

# Define credential keywords pattern
credential_keywords := `(password|secret|token|key|credential|passphrase|api_key|access_key|private_key|client_secret|db_password|admin_password|user|keystore|truststore)`

# Helper function to check if a value is a hardcoded credential (string literal)
is_hardcoded_credential(value) {
    value.ir_type == "String"
    value.value != ""
    # Exclude values that look like paths or non-secret strings
    not regex.match(`^(?:/|[a-zA-Z]:\\)`, value.value)
    not regex.match(`^(true|false|null|nil)$`, value.value)
    not regex.match(`^\d+$`, value.value)
}

# Rule 1: Check variables with credential-related names
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    variable := variables[_]
    variable.ir_type == "Variable"
    regex.match(credential_keywords, variable.name)
    is_hardcoded_credential(variable.value)
    result := {
        "type": "sec_hard_secr",
        "element": variable,
        "path": parent.path,
        "description": "Hard-coded credentials in IaC script - Avoid storing credentials in source code. (CWE-798)"
    }
}

# Rule 2: Check attributes with credential-related names
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attribute := attributes[_]
    attribute.ir_type == "Attribute"
    regex.match(credential_keywords, attribute.name)
    is_hardcoded_credential(attribute.value)
    result := {
        "type": "sec_hard_secr",
        "element": attribute,
        "path": parent.path,
        "description": "Hard-coded credentials in IaC script - Avoid storing credentials in source code. (CWE-798)"
    }
}

# Rule 3: Check hash key-value pairs in complex values
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    key := pair.key
    value := pair.value
    key.ir_type == "String"
    regex.match(credential_keywords, key.value)
    is_hardcoded_credential(value)
    result := {
        "type": "sec_hard_secr",
        "element": value,
        "path": parent.path,
        "description": "Hard-coded credentials in IaC script - Avoid storing credentials in source code. (CWE-798)"
    }
}