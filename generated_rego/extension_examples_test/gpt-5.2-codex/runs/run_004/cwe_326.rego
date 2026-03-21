package glitch

import data.glitch_lib

crypto_field_patterns := {
  "encrypt", "encryption", "cipher", "cipher_suite", "algorithm", "crypto", "crypt",
  "hash", "digest", "auth_method", "auth_type", "auth", "password", "passphrase",
  "secret", "credential", "token", "key_spec", "key_type", "key_algorithm",
  "private_key", "public_key"
}

key_length_fields := {
  "key_length", "key_size", "key_bits", "rsa_bits", "dsa_bits", "dh_bits",
  "dh_parameter_size", "curve", "certificate_key_size", "certificate_key_length",
  "rsa_key_size", "dsa_key_size", "dh_key_size"
}

protocol_fields := {
  "tls_version", "min_tls_version", "ssl_version", "protocol", "protocols",
  "allowed_protocols", "security_policy", "ssl_protocol", "tls_protocol"
}

cipher_fields := {
  "cipher_suites", "allowed_ciphers", "allowed_cipher_suites",
  "cipher_suite", "cipher", "ssl_policy"
}

policy_fields := {
  "encryption_policy", "security_policy", "ssl_policy", "tls_policy", "security_profile"
}

weak_algo_keywords := {
  "des", "3des", "rc2", "rc4", "idea", "blowfish", "seed", "xor",
  "null", "export", "low", "weak", "legacy", "md5", "md4", "md2",
  "sha1", "sha-1"
}

weak_protocol_keywords := {
  "sslv2", "sslv3", "tls1.0", "tls1.1", "tlsv1", "tlsv1.0", "tlsv1.1",
  "legacy", "compatibility"
}

weak_cipher_keywords := {
  "rc4", "des", "3des", "export", "adh", "anon", "null", "md5", "sha1", "low", "weak"
}

weak_policy_keywords := {
  "default", "legacy", "compatible", "compatibility", "pre-tls1.2", "pretls1.2", "pre_tls1.2"
}

weak_sizes := {40, 56, 64, 80, 112, 512, 1024}

contains_any(str, patterns) {
  p := patterns[_]
  glitch_lib.contains(str, p)
}

field_matches(name, patterns) {
  contains_any(name, patterns)
}

key_value(parent, name, value, element) {
  kv := glitch_lib.all_attributes(parent)[_]
  name := kv.name
  value := kv.value
  element := kv
}

key_value(parent, name, value, element) {
  kv := glitch_lib.all_variables(parent)[_]
  name := kv.name
  value := kv.value
  element := kv
}

key_value(parent, name, value, element) {
  walk(parent, [_, h])
  h.ir_type == "Hash"
  kv := h.value[_]
  k := kv.key
  v := kv.value
  k.ir_type == "String"
  name := k.value
  value := v
  element := v
}

key_value(parent, name, value, element) {
  walk(parent, [_, h])
  h.ir_type == "Hash"
  kv := h.value[_]
  k := kv.key
  v := kv.value
  k.ir_type == "VariableReference"
  name := k.value
  value := v
  element := v
}

value_has_keyword(val, keywords) {
  kw := keywords[_]
  walk(val, [_, n])
  n.ir_type == "String"
  glitch_lib.contains(n.value, kw)
}

value_has_keyword(val, keywords) {
  kw := keywords[_]
  walk(val, [_, n])
  n.ir_type == "VariableReference"
  glitch_lib.contains(n.value, kw)
}

value_has_keyword(val, keywords) {
  kw := keywords[_]
  walk(val, [_, n])
  n.ir_type == "FunctionCall"
  glitch_lib.contains(n.name, kw)
}

value_has_keyword(val, keywords) {
  kw := keywords[_]
  walk(val, [_, n])
  n.ir_type == "MethodCall"
  glitch_lib.contains(n.method, kw)
}

is_asym_field(name) {
  regex.match("(?i).*(rsa|dsa|dh|certificate|cert|public|private|keypair).*", name)
}

weak_key_num(name, num) {
  num == weak_sizes[_]
}

weak_key_num(name, num) {
  is_asym_field(name)
  num < 2048
}

weak_key_length_value(name, val) {
  walk(val, [_, n])
  n.ir_type == "Integer"
  num := n.value
  weak_key_num(name, num)
}

weak_key_length_value(name, val) {
  walk(val, [_, n])
  n.ir_type == "String"
  regex.match("^[0-9]+$", n.value)
  num := to_number(n.value)
  weak_key_num(name, num)
}

weak_key_length_value(name, val) {
  walk(val, [_, n])
  n.ir_type == "String"
  regex.match("(?i).*p-?192.*", n.value)
}

weak_key_length_value(name, val) {
  walk(val, [_, n])
  n.ir_type == "String"
  regex.match("(?i).*p-?224.*", n.value)
}

Glitch_Analysis[result] {
  parent := glitch_lib._gather_parent_unit_blocks[_]
  parent.path != ""
  key_value(parent, name, value, element)
  field_matches(name, crypto_field_patterns)
  value_has_keyword(value, weak_algo_keywords) or contains_any(name, weak_algo_keywords)

  result := {
    "type": "sec_weak_crypt",
    "element": element,
    "path": parent.path,
    "description": "Weak or deprecated cryptographic algorithm or hash configured. (CWE-326)"
  }
}

Glitch_Analysis[result] {
  parent := glitch_lib._gather_parent_unit_blocks[_]
  parent.path != ""
  key_value(parent, name, value, element)
  field_matches(name, key_length_fields)
  weak_key_length_value(name, value)

  result := {
    "type": "sec_weak_crypt",
    "element": element,
    "path": parent.path,
    "description": "Insufficient cryptographic key length configured. (CWE-326)"
  }
}

Glitch_Analysis[result] {
  parent := glitch_lib._gather_parent_unit_blocks[_]
  parent.path != ""
  key_value(parent, name, value, element)
  field_matches(name, protocol_fields)
  value_has_keyword(value, weak_protocol_keywords)

  result := {
    "type": "sec_weak_crypt",
    "element": element,
    "path": parent.path,
    "description": "Outdated or insecure TLS/SSL protocol configured. (CWE-326)"
  }
}

Glitch_Analysis[result] {
  parent := glitch_lib._gather_parent_unit_blocks[_]
  parent.path != ""
  key_value(parent, name, value, element)
  field_matches(name, cipher_fields)
  value_has_keyword(value, weak_cipher_keywords)

  result := {
    "type": "sec_weak_crypt",
    "element": element,
    "path": parent.path,
    "description": "Weak cipher suite configured. (CWE-326)"
  }
}

Glitch_Analysis[result] {
  parent := glitch_lib._gather_parent_unit_blocks[_]
  parent.path != ""
  key_value(parent, name, value, element)
  field_matches(name, policy_fields)
  value_has_keyword(value, weak_policy_keywords)

  result := {
    "type": "sec_weak_crypt",
    "element": element,
    "path": parent.path,
    "description": "Legacy or weak encryption policy configured. (CWE-326)"
  }
}