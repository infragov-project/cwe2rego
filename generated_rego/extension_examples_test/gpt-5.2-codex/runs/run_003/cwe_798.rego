package glitch

import data.glitch_lib

cred_desc := "Use of hard-coded credentials - Credentials should not be embedded directly in IaC files. (CWE-798)"

delim := "[._:\\[\\]'_-]"

secret_keywords := {
  "password",
  "passwd",
  "pwd",
  "passphrase",
  "secret",
  "shared[_-]?secret",
  "client[_-]?secret",
  "token",
  "auth[_-]?token",
  "access[_-]?token",
  "refresh[_-]?token",
  "api[_-]?key",
  "apikey",
  "access[_-]?key",
  "secret[_-]?key",
  "private[_-]?key",
  "key_data",
  "ssh[_-]?key",
  "rsa[_-]?key",
  "tls[_-]?key",
  "certificate",
  "pem",
  "credential",
  "basic[_-]?auth",
  "bearer",
  "community[_-]?string",
  "snmp[_-]?community",
  "db[_-]?password",
  "ldap[_-]?password",
  "smtp[_-]?password",
  "mq[_-]?password",
  "service[_-]?account[_-]?password",
  "service[_-]?key"
}

common_user_values := {"root", "administrator"}

embedded_patterns := {
  "(?i).*[^/\\s:]+:[^@\\s]+@.*",
  "(?i).*(password|passwd|pwd|token|api[_-]?key|apikey|access[_-]?key|secret[_-]?key|auth[_-]?token)=\\S+.*",
  "(?is).*-----BEGIN[^-]*PRIVATE KEY-----.*",
  "(?i).*ssh-rsa\\s+[A-Za-z0-9+/=]+.*",
  "(?i).*\\bBearer\\s+[A-Za-z0-9\\-\\._]+.*"
}

ignore_name(name) {
  n := lower(name)
  regex.match(".*(no_password|nopassword|passwordless|disable_password|password_policy|password_min|password_max|password_length|password_history).*", n)
} else {
  n := lower(name)
  regex.match(".*(token_count|token_limit|token_limits|token_max|token_min|token_threshold|token_ttl|token_expir|token_timeout|num_tokens).*", n)
} else {
  n := lower(name)
  regex.match(".*(public_key|ssh_public_key).*", n)
}

secret_field(name) {
  n := lower(name)
  kw := secret_keywords[_]
  regex.match(sprintf("(^|%s)%s(%s|$)", [delim, kw, delim]), n)
}

key_field(name) {
  n := lower(name)
  regex.match(sprintf("(^|%s)key$", [delim]), n)
}

user_field(name) {
  n := lower(name)
  regex.match(sprintf("(^|%s)user(%s)?name$", [delim, delim]), n)
} else {
  n := lower(name)
  regex.match(sprintf("(^|%s)user$", [delim]), n)
} else {
  n := lower(name)
  regex.match(sprintf("(^|%s)login$", [delim]), n)
} else {
  n := lower(name)
  regex.match(sprintf("(^|%s)account$", [delim]), n)
}

dn_like(s) {
  regex.match(".*=.*,.+", s)
}

common_user_value(s) {
  common_user_values[lower(s)]
}

path_like(s) {
  regex.match("(?i)^(?:[a-z]:\\\\|/|\\./|\\.\\./|~\\/)", s)
} else {
  regex.match("(?i).*\\.(pem|crt|cer|key|p12|pfx|der|jks|keystore|truststore|xml|json|yml|yaml|conf|cfg|ini|txt|erb)$", s)
}

ok_secret_value(v) {
  v.ir_type == "String"
  not path_like(v.value)
} else {
  v.ir_type == "Integer"
} else {
  v.ir_type == "Float"
}

ok_key_value(v) {
  v.ir_type == "String"
  not path_like(v.value)
}

ok_user_value(v) {
  v.ir_type == "String"
  not path_like(v.value)
  not dn_like(v.value)
  not common_user_value(v.value)
}

credential_match(name, value) {
  secret_field(name)
  ok_secret_value(value)
} else {
  key_field(name)
  ok_key_value(value)
} else {
  user_field(name)
  ok_user_value(value)
}

cred_kv(name, value) {
  not ignore_name(name)
  credential_match(name, value)
}

embedded_credential(s) {
  pattern := embedded_patterns[_]
  regex.match(pattern, s)
}

Glitch_Analysis[result] {
  parent := glitch_lib._gather_parent_unit_blocks[_]
  parent.path != ""
  v := glitch_lib.all_variables(parent)[_]
  cred_kv(v.name, v.value)

  result := {
    "type": "sec_hard_secr",
    "element": v,
    "path": parent.path,
    "description": cred_desc
  }
}

Glitch_Analysis[result] {
  parent := glitch_lib._gather_parent_unit_blocks[_]
  parent.path != ""
  a := glitch_lib.all_attributes(parent)[_]
  cred_kv(a.name, a.value)

  result := {
    "type": "sec_hard_secr",
    "element": a,
    "path": parent.path,
    "description": cred_desc
  }
}

Glitch_Analysis[result] {
  parent := glitch_lib._gather_parent_unit_blocks[_]
  parent.path != ""
  walk(parent, [_, h])
  h.ir_type == "Hash"
  entry := h.value[_]
  entry.key.ir_type == "String"
  name := entry.key.value
  cred_kv(name, entry.value)

  result := {
    "type": "sec_hard_secr",
    "element": entry.value,
    "path": parent.path,
    "description": cred_desc
  }
}

Glitch_Analysis[result] {
  parent := glitch_lib._gather_parent_unit_blocks[_]
  parent.path != ""
  walk(parent, [_, s])
  s.ir_type == "String"
  embedded_credential(s.value)

  result := {
    "type": "sec_hard_secr",
    "element": s,
    "path": parent.path,
    "description": cred_desc
  }
}