package glitch

import data.glitch_lib

import future.keywords.in

credential_keywords := {"password", "passwd", "pwd", "secret", "passphrase", "credential", "api_key", "apikey", "api_secret", "access_key", "secret_key", "token", "bearer", "jwt_secret", "auth_token", "private_key", "ssh_key", "encryption_key", "decryption_key", "symmetric_key", "hmac_key", "salt", "keystore_password", "truststore_password", "sha512_password"}

context_keywords := {"cvauth", "auth", "credential", "encrypt", "keystore", "truststore", "ssl", "tls", "login", "account", "encryption"}

context_credential_fields := {"key", "password", "secret", "token", "cert"}

is_credential_field(name) {
    lower_name := lower(name)
    keyword := credential_keywords[_]
    contains(lower_name, keyword)
}

has_credential_context(name) {
    lower_name := lower(name)
    keyword := context_keywords[_]
    contains(lower_name, keyword)
}

is_external_reference(str) {
    regex.match("(?i)(vault|secret[_-]?manager|kms|ssm|parameter[_-]?store|env|lookup|file\\(|data\\.|module\\.|var\\.|keyvault|\\{\\{|\\$\\{|\\$\\()", str)
}

is_file_path(str) {
    regex.match("^(\\./|\\.\\./|/|[a-zA-Z]:\\\\)", str)
}

is_common_non_credential(str) {
    lower_str := lower(str)
    lower_str in {"localhost", "root", "administrator", "admin", "true", "false", "nil", "null", "none", "all", ""}
}

is_credential_value(val) {
    val.ir_type == "String"
    count(val.value) > 0
    not is_external_reference(val.value)
    not is_file_path(val.value)
    not is_common_non_credential(val.value)
}

# Check direct hash entry for credential
check_hash_entry(entry, parent_is_context) = result {
    entry.key.ir_type == "String"
    key_name := entry.key.value
    is_credential_field(key_name)
    is_credential_value(entry.value)
    result = {
        "type": "sec_hard_secr",
        "element": {
            "ir_type": "KeyValue",
            "name": key_name,
            "value": entry.value,
            "line": entry.key.line,
            "column": entry.key.column,
            "end_line": entry.value.end_line,
            "end_column": entry.value.end_column
        },
        "path": "",
        "description": "Use of Hard-coded Credentials - Credentials should not be hard-coded in Infrastructure as Code scripts. Use secure secret management instead. (CWE-798)"
    }
} else = result {
    entry.key.ir_type == "String"
    key_name := entry.key.value
    parent_is_context
    lower(key_name) == context_credential_fields[_]
    is_credential_value(entry.value)
    result = {
        "type": "sec_hard_secr",
        "element": {
            "ir_type": "KeyValue",
            "name": key_name,
            "value": entry.value,
            "line": entry.key.line,
            "column": entry.key.column,
            "end_line": entry.value.end_line,
            "end_column": entry.value.end_column
        },
        "path": "",
        "description": "Use of Hard-coded Credentials - Credentials should not be hard-coded in Infrastructure as Code scripts. Use secure secret management instead. (CWE-798)"
    }
}

# Recursively walk hashes to find credential entries
walk_hash_entries(hash, parent_is_context) = results {
    results = {r |
        some entry in hash.value
        entry.key.ir_type == "String"
        
        # Check this entry
        check_entry := check_hash_entry(entry, parent_is_context)
        check_entry != null
        
        # Set path from the hash's context
        r := {
            "type": check_entry.type,
            "element": check_entry.element,
            "path": check_entry.path,
            "description": check_entry.description
        }
    } | {r |
        # Recurse into nested hashes
        some entry in hash.value
        entry.value.ir_type == "Hash"
        
        new_context := parent_is_context == true || (entry.key.ir_type == "String" && has_credential_context(entry.key.value))
        
        nested := walk_hash_entries(entry.value, new_context)
        some n in nested
        
        r := n
    }
}

default check_hash_entry(entry, parent_is_context) = null

default walk_hash_entries(hash, parent_is_context) = set()

# Main detection for Variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some node in parent.variables
    
    # Direct credential field name match
    is_credential_field(node.name)
    is_credential_value(node.value)
    
    result = {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials should not be hard-coded in Infrastructure as Code scripts. Use secure secret management instead. (CWE-798)"
    }
}

# Check Variables with Hash values that may contain credentials
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some node in parent.variables
    node.value.ir_type == "Hash"
    
    # Check if variable name itself suggests credential context
    var_is_context := has_credential_context(node.name)
    
    # Walk all nested hash entries
    found := walk_hash_entries(node.value, var_is_context)
    count(found) > 0
    
    some res in found
    
    result = {
        "type": res.type,
        "element": res.element,
        "path": parent.path,
        "description": res.description
    }
}

# Check Attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some node in parent.attributes
    
    is_credential_field(node.name)
    is_credential_value(node.value)
    
    result = {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials should not be hard-coded in Infrastructure as Code scripts. Use secure secret management instead. (CWE-798)"
    }
}

# Check Attributes with Hash values
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some node in parent.attributes
    node.value.ir_type == "Hash"
    
    var_is_context := has_credential_context(node.name)
    
    found := walk_hash_entries(node.value, var_is_context)
    count(found) > 0
    
    some res in found
    
    result = {
        "type": res.type,
        "element": res.element,
        "path": parent.path,
        "description": res.description
    }
}

# Check Variables inside ConditionalStatements
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some cond in parent.statements
    cond.ir_type == "ConditionalStatement"
    
    some stmt in cond.statements
    stmt.ir_type == "Variable"
    
    is_credential_field(stmt.name)
    is_credential_value(stmt.value)
    
    result = {
        "type": "sec_hard_secr",
        "element": stmt,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials should not be hard-coded in Infrastructure as Code scripts. Use secure secret management instead. (CWE-798)"
    }
}

# Check Variables with Hash values inside Conditionals
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some cond in parent.statements
    cond.ir_type == "ConditionalStatement"
    
    some stmt in cond.statements
    stmt.ir_type == "Variable"
    stmt.value.ir_type == "Hash"
    
    var_is_context := has_credential_context(stmt.name)
    
    found := walk_hash_entries(stmt.value, var_is_context)
    count(found) > 0
    
    some res in found
    
    result = {
        "type": res.type,
        "element": res.element,
        "path": parent.path,
        "description": res.description
    }
}

# Check else_statement of Conditionals
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some cond in parent.statements
    cond.ir_type == "ConditionalStatement"
    cond.else_statement != null
    
    some stmt in cond.else_statement.statements
    stmt.ir_type == "Variable"
    
    is_credential_field(stmt.name)
    is_credential_value(stmt.value)
    
    result = {
        "type": "sec_hard_secr",
        "element": stmt,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials should not be hard-coded in Infrastructure as Code scripts. Use secure secret management instead. (CWE-798)"
    }
}

# Check else_statement with Hash values
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some cond in parent.statements
    cond.ir_type == "ConditionalStatement"
    cond.else_statement != null
    
    some stmt in cond.else_statement.statements
    stmt.ir_type == "Variable"
    stmt.value.ir_type == "Hash"
    
    var_is_context := has_credential_context(stmt.name)
    
    found := walk_hash_entries(stmt.value, var_is_context)
    count(found) > 0
    
    some res in found
    
    result = {
        "type": res.type,
        "element": res.element,
        "path": parent.path,
        "description": res.description
    }
}

# Direct Hash walk from UnitBlock statements (for Ansible-style nested structures)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Hash"
    
    found := walk_hash_entries(node, false)
    count(found) > 0
    
    some res in found
    
    result = {
        "type": res.type,
        "element": res.element,
        "path": parent.path,
        "description": res.description
    }
}