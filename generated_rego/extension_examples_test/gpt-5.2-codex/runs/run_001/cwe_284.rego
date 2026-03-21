package glitch

import data.glitch_lib

public_name_pattern := "(?i).*(public|anonymous|unauthenticated|guest|allow_public|public_access|enable_public|anonymous_access).*"
access_name_pattern := "(?i).*(access|acl|policy|permission|permissions|principal|member|subject|public|anonymous).*"
principal_name_pattern := "(?i).*(principal|member|subject|user|group|account|identity).*"
policy_name_pattern := "(?i).*(policy|permission|permissions|action|actions|resource|resources|scope|access).*"
network_name_pattern := "(?i).*(cidr|source|ingress|egress|ip|network|address|range|firewall|rule|from|remote).*"
auth_name_pattern := "(?i).*(auth|authorization|authentication|enforce|acl|policy|permission|permissions|access_control).*"
role_name_pattern := "(?i).*(role|privilege|privileged|access_level|accesslevel|group).*"
trust_name_pattern := "(?i).*(trust|trusted|assume|delegat|external).*"
file_perm_name_pattern := "(?i).*(mode|permission|permissions|perm|chmod|file_mode|file_permission).*"

public_value_pattern := "(?i).*(public|anonymous|unauthenticated|guest|allusers|allauthenticatedusers|everyone|anyone|public-read-write).*"
privileged_value_pattern := "(?i).*(admin|owner|root|superuser|full_access|privileged).*"
disabled_value_pattern := "(?i).*(none|disabled|off|no|false|disable_auth|bypass|ignore_acl|bypass_policy).*"
anyall_pattern := "(?i)^(all|any|everyone|anyone|allusers|allauthenticatedusers)$"
wildcard_pattern := "(?i)^\\*$"
open_cidr_pattern := "(?i).*(0\\.0\\.0\\.0/0|::/0).*"
trust_value_pattern := "(?i).*(external|any_account|all_accounts).*"

all_kvs(parent)[kv] {
    kv := glitch_lib.all_attributes(parent)[_]
}

all_kvs(parent)[kv] {
    kv := glitch_lib.all_variables(parent)[_]
}

name_matches(name, pattern) {
    regex.match(pattern, name)
}

value_has_pattern(value, pattern) {
    glitch_lib.traverse(value, pattern)
}

value_is_true(value) {
    walk(value, [_, n])
    n.ir_type == "Boolean"
    n.value == true
}

value_is_true(value) {
    walk(value, [_, n])
    n.ir_type == "String"
    regex.match("(?i)^(true|yes|on|enabled|enable|allow)$", n.value)
}

value_is_false(value) {
    walk(value, [_, n])
    n.ir_type == "Boolean"
    n.value == false
}

value_is_false(value) {
    walk(value, [_, n])
    n.ir_type == "String"
    regex.match("(?i)^(false|no|off|disabled|disable)$", n.value)
}

value_is_null_or_empty(value) {
    walk(value, [_, n])
    n.ir_type == "Null"
}

value_is_null_or_empty(value) {
    walk(value, [_, n])
    n.ir_type == "Undef"
}

value_is_null_or_empty(value) {
    walk(value, [_, n])
    n.ir_type == "String"
    n.value == ""
}

value_is_disabled(value) {
    value_is_false(value)
}

value_is_disabled(value) {
    value_has_pattern(value, disabled_value_pattern)
}

value_is_disabled(value) {
    value_is_null_or_empty(value)
}

value_has_world_permission(value) {
    walk(value, [_, n])
    n.ir_type == "Integer"
    n.value == 777
}

value_has_world_permission(value) {
    walk(value, [_, n])
    n.ir_type == "Integer"
    n.value == 666
}

value_has_world_permission(value) {
    walk(value, [_, n])
    n.ir_type == "String"
    regex.match("(?i)^(0?777|0?666)$", n.value)
}

value_has_world_permission(value) {
    walk(value, [_, n])
    n.ir_type == "String"
    regex.match("(?i)(public-read-write|world_writable|everyone_read|everyone_write|(?:^|(?:ugo)|o|a)\\+[rwx]{3})", n.value)
}

value_is_open(value) {
    value_has_pattern(value, open_cidr_pattern)
}

value_is_open(value) {
    value_has_pattern(value, wildcard_pattern)
}

value_is_open(value) {
    value_has_pattern(value, anyall_pattern)
}

public_access_kv(kv) {
    name_matches(kv.name, public_name_pattern)
    value_is_true(kv.value)
}

public_access_kv(kv) {
    name_matches(kv.name, public_name_pattern)
    value_has_pattern(kv.value, public_value_pattern)
}

public_access_kv(kv) {
    name_matches(kv.name, access_name_pattern)
    value_has_pattern(kv.value, public_value_pattern)
}

wildcard_principal_kv(kv) {
    name_matches(kv.name, principal_name_pattern)
    value_has_pattern(kv.value, wildcard_pattern)
}

wildcard_principal_kv(kv) {
    name_matches(kv.name, principal_name_pattern)
    value_has_pattern(kv.value, anyall_pattern)
}

overly_permissive_policy_kv(kv) {
    name_matches(kv.name, policy_name_pattern)
    value_has_pattern(kv.value, wildcard_pattern)
}

overly_permissive_policy_kv(kv) {
    name_matches(kv.name, policy_name_pattern)
    value_has_pattern(kv.value, anyall_pattern)
}

overly_permissive_policy_kv(kv) {
    name_matches(kv.name, policy_name_pattern)
    value_has_pattern(kv.value, privileged_value_pattern)
}

world_permission_kv(kv) {
    name_matches(kv.name, file_perm_name_pattern)
    value_has_world_permission(kv.value)
}

open_network_kv(kv) {
    name_matches(kv.name, network_name_pattern)
    value_is_open(kv.value)
}

disabled_access_kv(kv) {
    name_matches(kv.name, auth_name_pattern)
    value_is_disabled(kv.value)
}

privileged_role_kv(kv) {
    name_matches(kv.name, role_name_pattern)
    value_has_pattern(kv.value, privileged_value_pattern)
}

trust_broad_kv(kv) {
    name_matches(kv.name, trust_name_pattern)
    value_has_pattern(kv.value, wildcard_pattern)
}

trust_broad_kv(kv) {
    name_matches(kv.name, trust_name_pattern)
    value_has_pattern(kv.value, anyall_pattern)
}

trust_broad_kv(kv) {
    name_matches(kv.name, trust_name_pattern)
    value_has_pattern(kv.value, trust_value_pattern)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    kv := all_kvs(parent)[_]
    public_access_kv(kv)
    result := {
        "type": "sec_invalid_bind",
        "element": kv,
        "path": parent.path,
        "description": "Public or anonymous access enabled - Access control allows unrestricted public access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    kv := all_kvs(parent)[_]
    wildcard_principal_kv(kv)
    result := {
        "type": "sec_invalid_bind",
        "element": kv,
        "path": parent.path,
        "description": "Wildcard or unrestricted principal in access control configuration. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    kv := all_kvs(parent)[_]
    overly_permissive_policy_kv(kv)
    result := {
        "type": "sec_invalid_bind",
        "element": kv,
        "path": parent.path,
        "description": "Overly permissive policy grants full access to actions or resources. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    kv := all_kvs(parent)[_]
    world_permission_kv(kv)
    result := {
        "type": "sec_invalid_bind",
        "element": kv,
        "path": parent.path,
        "description": "World-readable or world-writable permissions detected. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    kv := all_kvs(parent)[_]
    open_network_kv(kv)
    result := {
        "type": "sec_invalid_bind",
        "element": kv,
        "path": parent.path,
        "description": "Security rule open to the entire internet. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    kv := all_kvs(parent)[_]
    disabled_access_kv(kv)
    result := {
        "type": "sec_invalid_bind",
        "element": kv,
        "path": parent.path,
        "description": "Access controls disabled or not enforced. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    kv := all_kvs(parent)[_]
    privileged_role_kv(kv)
    result := {
        "type": "sec_invalid_bind",
        "element": kv,
        "path": parent.path,
        "description": "Privileged role assigned broadly, violating least privilege. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    kv := all_kvs(parent)[_]
    trust_broad_kv(kv)
    result := {
        "type": "sec_invalid_bind",
        "element": kv,
        "path": parent.path,
        "description": "Trust relationship too broad or unrestricted. (CWE-284)"
    }
}