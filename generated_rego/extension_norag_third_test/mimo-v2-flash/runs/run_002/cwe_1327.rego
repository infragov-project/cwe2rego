package glitch

import data.glitch_lib

binding_keywords := {"bind_address", "listen_address", "host", "ip_address", "server_address", "interface", "bind-address", "ip", "addr", "address"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variable := glitch_lib.all_variables(parent)[_]
    variable.value.ir_type == "String"
    variable.value.value == "0.0.0.0"
    lower_name := lower(variable.name)
    contains(lower_name, binding_keywords[_])
    result := {
        "type": "sec_invalid_bind",
        "element": variable,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address (0.0.0.0) - This may allow external actors to connect to the service. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variable := glitch_lib.all_variables(parent)[_]
    variable.value.ir_type == "Hash"
    pair := variable.value.value[_]
    pair.key.ir_type == "String"
    contains(lower(pair.key.value), binding_keywords[_])
    pair.value.ir_type == "String"
    pair.value.value == "0.0.0.0"
    result := {
        "type": "sec_invalid_bind",
        "element": variable,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address (0.0.0.0) - This may allow external actors to connect to the service. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variable := glitch_lib.all_variables(parent)[_]
    variable.value.ir_type == "Hash"
    pair := variable.value.value[_]
    pair.value.ir_type == "Hash"
    nested_pair := pair.value.value[_]
    nested_pair.key.ir_type == "String"
    contains(lower(nested_pair.key.value), binding_keywords[_])
    nested_pair.value.ir_type == "String"
    nested_pair.value.value == "0.0.0.0"
    result := {
        "type": "sec_invalid_bind",
        "element": variable,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address (0.0.0.0) - This may allow external actors to connect to the service. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attribute := glitch_lib.all_attributes(parent)[_]
    attribute.value.ir_type == "String"
    attribute.value.value == "0.0.0.0"
    lower_name := lower(attribute.name)
    contains(lower_name, binding_keywords[_])
    result := {
        "type": "sec_invalid_bind",
        "element": attribute,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address (0.0.0.0) - This may allow external actors to connect to the service. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attribute := glitch_lib.all_attributes(parent)[_]
    attribute.value.ir_type == "Hash"
    pair := attribute.value.value[_]
    pair.key.ir_type == "String"
    contains(lower(pair.key.value), binding_keywords[_])
    pair.value.ir_type == "String"
    pair.value.value == "0.0.0.0"
    result := {
        "type": "sec_invalid_bind",
        "element": attribute,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address (0.0.0.0) - This may allow external actors to connect to the service. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attribute := glitch_lib.all_attributes(parent)[_]
    attribute.value.ir_type == "Hash"
    pair := attribute.value.value[_]
    pair.value.ir_type == "Hash"
    nested_pair := pair.value.value[_]
    nested_pair.key.ir_type == "String"
    contains(lower(nested_pair.key.value), binding_keywords[_])
    nested_pair.value.ir_type == "String"
    nested_pair.value.value == "0.0.0.0"
    result := {
        "type": "sec_invalid_bind",
        "element": attribute,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address (0.0.0.0) - This may allow external actors to connect to the service. (CWE-1327)"
    }
}