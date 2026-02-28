package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditions := glitch_lib.all_conditional_statements(parent)
    condition := conditions[_]
    condition.type == ConditionalStatement.ConditionType.SWITCH
    not any(condition_, conditions, condition_.is_default)
    condition.statements[0].ir_type == "ConditionalStatement"
    condition.statements[0].is_default == false
    result := {
        "type": "sec_no_default_switch",
        "element": condition,
        "path": parent.path,
        "description": "Missing default case in multiple condition expression - A switch-like conditional structure lacks a default fallback, risking undefined behavior for unexpected inputs. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditions := glitch_lib.all_conditional_statements(parent)
    condition := conditions[_]
    condition.type == ConditionalStatement.ConditionType.IF
    condition.else_statement == null
    condition.statements[0].ir_type == "ConditionalStatement"
    condition.statements[0].is_default == false
    result := {
        "type": "sec_no_default_switch",
        "element": condition,
        "path": parent.path,
        "description": "Missing default case in multiple condition expression - An if-elif chain lacks an else fallback, risking undefined behavior for unexpected inputs. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "lookup" or attr.name == "map" or attr.name == "values" or attr.name == "options"
    attr.value.ir_type == "FunctionCall"
    attr.value.name == "lookup" or attr.value.name == "map" or attr.value.name == "values" or attr.value.name == "options"
    not any(arg, attr.value.args, arg.ir_type == "Value" and arg.value == null)
    not any(arg, attr.value.args, arg.ir_type == "Value" and arg.value == Undef())
    not any(arg, attr.value.args, arg.ir_type == "VariableReference" and arg.value == "default")
    not any(arg, attr.value.args, arg.ir_type == "String" and arg.value == "default")
    result := {
        "type": "sec_no_default_switch",
        "element": attr,
        "path": parent.path,
        "description": "Missing default case in map or lookup operation - A lookup or map operation is used without a default fallback, risking undefined behavior for unknown keys. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditions := glitch_lib.all_conditional_statements(parent)
    condition := conditions[_]
    condition.type == ConditionalStatement.ConditionType.IF
    condition.else_statement == null
    not any(child, condition.statements, child.ir_type == "ConditionalStatement" and child.is_default)
    result := {
        "type": "sec_no_default_switch",
        "element": condition,
        "path": parent.path,
        "description": "Missing default case in multiple condition expression - An if-elif chain lacks a fallback, risking undefined behavior for unexpected inputs. (CWE-478)"
    }
}