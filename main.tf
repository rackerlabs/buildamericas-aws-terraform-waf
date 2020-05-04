terraform {
  required_version = ">= 0.12"

  required_providers {
    aws = ">= 2.60.0"
  }
}

locals {
  tags = {
    Environment     = var.environment
    ServiceProvider = "Rackspace"
  }
}

##### OWASP 1: Mitigate SQL Injection Attacks #####

resource "aws_waf_sql_injection_match_set" "sql_injection_match_set_global" {
  count = var.waf_global && var.create_rules == "true" ? 1 : 0
  name  = "sql_injection_match_set"

  sql_injection_match_tuples {
    text_transformation = "URL_DECODE"

    field_to_match {
      type = "URI"
    }
  }

  sql_injection_match_tuples {
    text_transformation = "HTML_ENTITY_DECODE"

    field_to_match {
      type = "URI"
    }
  }

  sql_injection_match_tuples {
    text_transformation = "URL_DECODE"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  sql_injection_match_tuples {
    text_transformation = "HTML_ENTITY_DECODE"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  sql_injection_match_tuples {
    text_transformation = "URL_DECODE"

    field_to_match {
      type = "BODY"
    }
  }

  sql_injection_match_tuples {
    text_transformation = "HTML_ENTITY_DECODE"

    field_to_match {
      type = "BODY"
    }
  }

  sql_injection_match_tuples {
    text_transformation = "URL_DECODE"

    field_to_match {
      data = "cookie"
      type = "HEADER"
    }
  }

  sql_injection_match_tuples {
    text_transformation = "HTML_ENTITY_DECODE"

    field_to_match {
      data = "cookie"
      type = "HEADER"
    }
  }
}

resource "aws_wafregional_sql_injection_match_set" "sql_injection_match_set_regional" {
  count = var.waf_regional && var.create_rules == "true" ? 1 : 0
  name  = "sql_injection_match_set"

  sql_injection_match_tuple {
    text_transformation = "URL_DECODE"

    field_to_match {
      type = "URI"
    }
  }

  sql_injection_match_tuple {
    text_transformation = "HTML_ENTITY_DECODE"

    field_to_match {
      type = "URI"
    }
  }

  sql_injection_match_tuple {
    text_transformation = "URL_DECODE"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  sql_injection_match_tuple {
    text_transformation = "HTML_ENTITY_DECODE"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  sql_injection_match_tuple {
    text_transformation = "URL_DECODE"

    field_to_match {
      type = "BODY"
    }
  }

  sql_injection_match_tuple {
    text_transformation = "HTML_ENTITY_DECODE"

    field_to_match {
      type = "BODY"
    }
  }

  sql_injection_match_tuple {
    text_transformation = "URL_DECODE"

    field_to_match {
      data = "cookie"
      type = "HEADER"
    }
  }

  sql_injection_match_tuple {
    text_transformation = "HTML_ENTITY_DECODE"

    field_to_match {
      data = "cookie"
      type = "HEADER"
    }
  }
}

resource "aws_waf_rule" "waf_sql_rule_global" {
  count       = var.waf_global && var.create_rules == "true" ? 1 : 0
  name        = "WAFSQLRule"
  metric_name = "WAFSQLRule"

  predicates {
    data_id = aws_waf_sql_injection_match_set.sql_injection_match_set_global.0.id
    negated = false
    type    = "SqlInjectionMatch"
  }
}

resource "aws_wafregional_rule" "waf_sql_rule_regional" {
  count       = var.waf_regional && var.create_rules == "true" ? 1 : 0
  name        = "WAFSQLRule"
  metric_name = "WAFSQLRule"

  predicate {
    data_id = aws_wafregional_sql_injection_match_set.sql_injection_match_set_regional.0.id
    negated = false
    type    = "SqlInjectionMatch"
  }
}

##### OWASP 2: Blacklist bad/hijacked JWT tokens or session IDs #####

resource "aws_waf_byte_match_set" "byte_set_jwt_global" {
  count = var.waf_global && var.create_rules == "true" ? 1 : 0
  name  = "waf_byte_match_set_jwt"

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "example-session-id"
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "HEADER"
      data = "cookie"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = ".TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "HEADER"
      data = "authorization"
    }
  }
}

resource "aws_wafregional_byte_match_set" "byte_set_jwt_regional" {
  count = var.waf_regional && var.create_rules == "true" ? 1 : 0
  name  = "waf_byte_match_set_jwt"

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "example-session-id"
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "HEADER"
      data = "cookie"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = ".TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "HEADER"
      data = "authorization"
    }
  }
}

resource "aws_waf_rule" "waf_jwt_rule_global" {
  count       = var.waf_global && var.create_rules == "true" ? 1 : 0
  name        = "WAFJWTRule"
  metric_name = "WAFJWTRule"

  predicates {
    data_id = aws_waf_byte_match_set.byte_set_jwt_global.0.id
    negated = false
    type    = "ByteMatch"
  }
}

resource "aws_wafregional_rule" "waf_jwt_rule_regional" {
  count       = var.waf_regional && var.create_rules == "true" ? 1 : 0
  name        = "WAFJWTRule"
  metric_name = "WAFJWTRule"

  predicate {
    data_id = aws_wafregional_byte_match_set.byte_set_jwt_regional.0.id
    negated = false
    type    = "ByteMatch"
  }
}

##### OWASP 3: Mitigate Cross Site Scripting Attacks ######

resource "aws_waf_xss_match_set" "xss_match_set_global" {
  count = var.waf_global && var.create_rules == "true" ? 1 : 0
  name  = "xss_match_set"

  xss_match_tuples {
    text_transformation = "URL_DECODE"

    field_to_match {
      type = "URI"
    }
  }

  xss_match_tuples {
    text_transformation = "HTML_ENTITY_DECODE"

    field_to_match {
      type = "URI"
    }
  }

  xss_match_tuples {
    text_transformation = "URL_DECODE"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  xss_match_tuples {
    text_transformation = "HTML_ENTITY_DECODE"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  xss_match_tuples {
    text_transformation = "URL_DECODE"

    field_to_match {
      type = "BODY"
    }
  }

  xss_match_tuples {
    text_transformation = "HTML_ENTITY_DECODE"

    field_to_match {
      type = "BODY"
    }
  }

  xss_match_tuples {
    text_transformation = "URL_DECODE"

    field_to_match {
      data = "cookie"
      type = "HEADER"
    }
  }

  xss_match_tuples {
    text_transformation = "HTML_ENTITY_DECODE"

    field_to_match {
      data = "cookie"
      type = "HEADER"
    }
  }
}

resource "aws_wafregional_xss_match_set" "xss_match_set_regional" {
  count = var.waf_regional && var.create_rules == "true" ? 1 : 0
  name  = "xss_match_set"

  xss_match_tuple {
    text_transformation = "URL_DECODE"

    field_to_match {
      type = "URI"
    }
  }

  xss_match_tuple {
    text_transformation = "HTML_ENTITY_DECODE"

    field_to_match {
      type = "URI"
    }
  }

  xss_match_tuple {
    text_transformation = "URL_DECODE"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  xss_match_tuple {
    text_transformation = "HTML_ENTITY_DECODE"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  xss_match_tuple {
    text_transformation = "URL_DECODE"

    field_to_match {
      type = "BODY"
    }
  }

  xss_match_tuple {
    text_transformation = "HTML_ENTITY_DECODE"

    field_to_match {
      type = "BODY"
    }
  }

  xss_match_tuple {
    text_transformation = "URL_DECODE"

    field_to_match {
      data = "cookie"
      type = "HEADER"
    }
  }

  xss_match_tuple {
    text_transformation = "HTML_ENTITY_DECODE"

    field_to_match {
      data = "cookie"
      type = "HEADER"
    }
  }
}

resource "aws_waf_rule" "waf_xss_rule_global" {
  count       = var.waf_global && var.create_rules == "true" ? 1 : 0
  name        = "WAFXSSRule"
  metric_name = "WAFXSSRule"

  predicates {
    data_id = aws_waf_xss_match_set.xss_match_set_global.0.id
    negated = false
    type    = "XssMatch"
  }
}

resource "aws_wafregional_rule" "waf_xss_rule_regional" {
  count       = var.waf_regional && var.create_rules == "true" ? 1 : 0
  name        = "WAFXSSRule"
  metric_name = "WAFXSSRule"

  predicate {
    data_id = aws_wafregional_xss_match_set.xss_match_set_regional.0.id
    negated = false
    type    = "XssMatch"
  }
}

##### OWASP 4: Path Traversal, LFI, RFI #####

resource "aws_waf_byte_match_set" "byte_set_paths_global" {
  count = var.waf_global && var.create_rules == "true" ? 1 : 0
  name  = "waf_byte_match_set_paths"

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "../"
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "HTML_ENTITY_DECODE"
    target_string         = "../"
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "../"
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "HTML_ENTITY_DECODE"
    target_string         = "../"
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "://"
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "HTML_ENTITY_DECODE"
    target_string         = "://"
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "://"
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "HTML_ENTITY_DECODE"
    target_string         = "://"
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }
}

resource "aws_wafregional_byte_match_set" "byte_set_paths_regional" {
  count = var.waf_regional && var.create_rules == "true" ? 1 : 0
  name  = "waf_byte_match_set_paths"

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "../"
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "HTML_ENTITY_DECODE"
    target_string         = "../"
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "../"
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "HTML_ENTITY_DECODE"
    target_string         = "../"
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "://"
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "HTML_ENTITY_DECODE"
    target_string         = "://"
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "://"
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "HTML_ENTITY_DECODE"
    target_string         = "://"
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }
}

resource "aws_waf_rule" "waf_path_rule_global" {
  count       = var.waf_global && var.create_rules == "true" ? 1 : 0
  name        = "WAFPathRule"
  metric_name = "WAFPathRule"

  predicates {
    data_id = aws_waf_byte_match_set.byte_set_paths_global.0.id
    negated = false
    type    = "ByteMatch"
  }
}

resource "aws_wafregional_rule" "waf_path_rule_regional" {
  count       = var.waf_regional && var.create_rules == "true" ? 1 : 0
  name        = "WAFPathRule"
  metric_name = "WAFPathRule"

  predicate {
    data_id = aws_wafregional_byte_match_set.byte_set_paths_regional.0.id
    negated = false
    type    = "ByteMatch"
  }
}

##### OWASP 5: Privileged Module Access Restrictions #####

resource "aws_waf_byte_match_set" "byte_set_admin_global" {
  count = var.waf_global && var.create_rules == "true" ? 1 : 0
  name  = "waf_byte_match_set_admin"

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = var.admin_path
    positional_constraint = "STARTS_WITH"

    field_to_match {
      type = "URI"
    }
  }
}

resource "aws_wafregional_byte_match_set" "byte_set_admin_regional" {
  count = var.waf_regional && var.create_rules == "true" ? 1 : 0
  name  = "waf_byte_match_set_admin"

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = var.admin_path
    positional_constraint = "STARTS_WITH"

    field_to_match {
      type = "URI"
    }
  }
}

resource "aws_waf_ipset" "ipset_admin_global" {
  count = var.waf_global && var.create_rules == "true" ? 1 : 0
  name  = "ipset_admin"

  ip_set_descriptors {
    type  = "IPV4"
    value = var.admin_cidr
  }
}

resource "aws_wafregional_ipset" "ipset_admin_regional" {
  count = var.waf_regional && var.create_rules == "true" ? 1 : 0
  name  = "ipset_admin"

  ip_set_descriptor {
    type  = "IPV4"
    value = var.admin_cidr
  }
}

resource "aws_waf_rule" "waf_admin_rule_global" {
  count       = var.waf_global && var.create_rules == "true" ? 1 : 0
  name        = "WAFAdminRule"
  metric_name = "WAFAdminRule"

  predicates {
    data_id = aws_waf_byte_match_set.byte_set_admin_global.0.id
    negated = false
    type    = "ByteMatch"
  }
  predicates {
    data_id = aws_waf_ipset.ipset_admin_global.0.id
    negated = true
    type    = "IPMatch"
  }
}

resource "aws_wafregional_rule" "waf_admin_rule_regional" {
  count       = var.waf_regional && var.create_rules == "true" ? 1 : 0
  name        = "WAFAdminRule"
  metric_name = "WAFAdminRule"

  predicate {
    data_id = aws_wafregional_byte_match_set.byte_set_admin_regional.0.id
    negated = false
    type    = "ByteMatch"
  }
  predicate {
    data_id = aws_wafregional_ipset.ipset_admin_regional.0.id
    negated = true
    type    = "IPMatch"
  }
}

##### OWASP 6: PHP Specific Security Misconfigurations #####
resource "aws_waf_byte_match_set" "byte_set_php_global" {
  count = var.waf_global && var.create_rules == "true" ? 1 : 0
  name  = "waf_byte_match_set_php"

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "_SERVER["
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "_ENV["
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "auto_prepend_file="
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "auto_append_file="
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "allow_url_include="
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "disable_functions="
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "open_basedir="
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "safe_mode="
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }
}

resource "aws_wafregional_byte_match_set" "byte_set_php_regional" {
  count = var.waf_regional && var.create_rules == "true" ? 1 : 0
  name  = "waf_byte_match_set_php"

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "_SERVER["
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "_ENV["
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "auto_prepend_file="
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "auto_append_file="
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "allow_url_include="
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "disable_functions="
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "open_basedir="
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "safe_mode="
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "QUERY_STRING"
    }
  }
}

resource "aws_waf_rule" "waf_php_rule_global" {
  count       = var.waf_global && var.create_rules == "true" ? 1 : 0
  name        = "WAFPHPRule"
  metric_name = "WAFPHPRule"

  predicates {
    data_id = aws_waf_byte_match_set.byte_set_php_global.0.id
    negated = false
    type    = "ByteMatch"
  }
}

resource "aws_wafregional_rule" "waf_php_rule_regional" {
  count       = var.waf_regional && var.create_rules == "true" ? 1 : 0
  name        = "WAFPHPRule"
  metric_name = "WAFPHPhRule"

  predicate {
    data_id = aws_wafregional_byte_match_set.byte_set_php_regional.0.id
    negated = false
    type    = "ByteMatch"
  }
}

##### OWASP 7: Mitigate abnormal requests via size restrictions #####

resource "aws_waf_size_constraint_set" "size_constraint_set_global" {
  count = var.waf_global && var.create_rules == "true" ? 1 : 0
  name  = "size_constraint"

  size_constraints {
    text_transformation = "NONE"
    comparison_operator = "GT"
    size                = "512"

    field_to_match {
      type = "URI"
    }
  }

  size_constraints {
    text_transformation = "NONE"
    comparison_operator = "GT"
    size                = "1024"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  size_constraints {
    text_transformation = "NONE"
    comparison_operator = "GT"
    size                = "4096"

    field_to_match {
      type = "BODY"
    }
  }

  size_constraints {
    text_transformation = "NONE"
    comparison_operator = "GT"
    size                = "4093"

    field_to_match {
      data = "cookie"
      type = "HEADER"
    }
  }
}

resource "aws_wafregional_size_constraint_set" "size_constraint_set_regional" {
  count = var.waf_regional && var.create_rules == "true" ? 1 : 0
  name  = "size_constraint"

  size_constraints {
    text_transformation = "NONE"
    comparison_operator = "GT"
    size                = "512"

    field_to_match {
      type = "URI"
    }
  }

  size_constraints {
    text_transformation = "NONE"
    comparison_operator = "GT"
    size                = "1024"

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  size_constraints {
    text_transformation = "NONE"
    comparison_operator = "GT"
    size                = "4096"

    field_to_match {
      type = "BODY"
    }
  }

  size_constraints {
    text_transformation = "NONE"
    comparison_operator = "GT"
    size                = "4093"

    field_to_match {
      data = "cookie"
      type = "HEADER"
    }
  }
}

resource "aws_waf_rule" "waf_size_rule_global" {
  count       = var.waf_global && var.create_rules == "true" ? 1 : 0
  name        = "WAFSizeRule"
  metric_name = "WAFSizeRule"

  predicates {
    data_id = aws_waf_size_constraint_set.size_constraint_set_global.0.id
    negated = false
    type    = "SizeConstraint"
  }
}

resource "aws_wafregional_rule" "waf_size_rule_regional" {
  count       = var.waf_regional && var.create_rules == "true" ? 1 : 0
  name        = "WAFSizeRule"
  metric_name = "WAFSizeRule"

  predicate {
    data_id = aws_wafregional_size_constraint_set.size_constraint_set_regional.0.id
    negated = false
    type    = "SizeConstraint"
  }
}

##### OWASP 8: CSRF token enforcement #####

resource "aws_waf_byte_match_set" "byte_set_csrf_method_global" {
  count = var.waf_global && var.create_rules == "true" ? 1 : 0
  name  = "waf_byte_match_set_csrf"

  byte_match_tuples {
    text_transformation   = "LOWERCASE"
    target_string         = "post"
    positional_constraint = "EXACTLY"

    field_to_match {
      type = "METHOD"
    }
  }
}

resource "aws_wafregional_byte_match_set" "byte_set_csrf_method_regional" {
  count = var.waf_regional && var.create_rules == "true" ? 1 : 0
  name  = "waf_byte_match_set_csrf"

  byte_match_tuples {
    text_transformation   = "LOWERCASE"
    target_string         = "post"
    positional_constraint = "EXACTLY"

    field_to_match {
      type = "METHOD"
    }
  }
}

resource "aws_waf_size_constraint_set" "size_constraint_csrf_global" {
  count = var.waf_global && var.create_rules == "true" ? 1 : 0
  name  = "size_constraint_csrf"

  size_constraints {
    text_transformation = "NONE"
    comparison_operator = "EQ"
    size                = "36"

    field_to_match {
      data = "x-csrf-token"
      type = "HEADER"
    }
  }
}

resource "aws_wafregional_size_constraint_set" "size_constraint_csrf_regional" {
  count = var.waf_regional && var.create_rules == "true" ? 1 : 0
  name  = "size_constraint_csrf"

  size_constraints {
    text_transformation = "NONE"
    comparison_operator = "EQ"
    size                = "36"

    field_to_match {
      data = "x-csrf-token"
      type = "HEADER"
    }
  }
}

resource "aws_waf_rule" "waf_csrf_rule_global" {
  count       = var.waf_global && var.create_rules == "true" ? 1 : 0
  name        = "WAFCSRFRule"
  metric_name = "WAFCSRFRule"

  predicates {
    data_id = aws_waf_byte_match_set.byte_set_csrf_method_global.0.id
    negated = false
    type    = "ByteMatch"
  }
  predicates {
    data_id = aws_waf_size_constraint_set.size_constraint_csrf_global.0.id
    negated = true
    type    = "SizeConstraint"
  }
}

resource "aws_wafregional_rule" "waf_csrf_rule_regional" {
  count       = var.waf_regional && var.create_rules == "true" ? 1 : 0
  name        = "WAFCSRFRule"
  metric_name = "WAFCSRFRule"

  predicate {
    data_id = aws_wafregional_byte_match_set.byte_set_csrf_method_regional.0.id
    negated = false
    type    = "ByteMatch"
  }
  predicate {
    data_id = aws_wafregional_size_constraint_set.size_constraint_csrf_regional.0.id
    negated = true
    type    = "SizeConstraint"
  }
}

##### OWASP 9: Server-side includes & libraries in webroot #####

resource "aws_waf_byte_match_set" "byte_set_includes_global" {
  count = var.waf_global && var.create_rules == "true" ? 1 : 0
  name  = "waf_byte_match_set_includes"

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "/includes"
    positional_constraint = "STARTS_WITH"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "LOWERCASE"
    target_string         = ".cfg"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "LOWERCASE"
    target_string         = ".conf"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "LOWERCASE"
    target_string         = ".config"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "LOWERCASE"
    target_string         = ".ini"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "LOWERCASE"
    target_string         = ".log"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "LOWERCASE"
    target_string         = ".bak"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "LOWERCASE"
    target_string         = ".backup"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "URI"
    }
  }
}

resource "aws_wafregional_byte_match_set" "byte_set_includes_regional" {
  count = var.waf_regional && var.create_rules == "true" ? 1 : 0
  name  = "waf_byte_match_set_includes"

  byte_match_tuples {
    text_transformation   = "URL_DECODE"
    target_string         = "/includes"
    positional_constraint = "STARTS_WITH"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "LOWERCASE"
    target_string         = ".cfg"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "LOWERCASE"
    target_string         = ".conf"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "LOWERCASE"
    target_string         = ".config"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "LOWERCASE"
    target_string         = ".ini"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "LOWERCASE"
    target_string         = ".log"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "LOWERCASE"
    target_string         = ".bak"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "URI"
    }
  }

  byte_match_tuples {
    text_transformation   = "LOWERCASE"
    target_string         = ".backup"
    positional_constraint = "ENDS_WITH"

    field_to_match {
      type = "URI"
    }
  }
}

resource "aws_waf_rule" "waf_includes_rule_global" {
  count       = var.waf_global && var.create_rules == "true" ? 1 : 0
  name        = "WAFIncludesRule"
  metric_name = "WAFIncludesRule"

  predicates {
    data_id = aws_waf_byte_match_set.byte_set_includes_global.0.id
    negated = false
    type    = "ByteMatch"
  }
}

resource "aws_wafregional_rule" "waf_includes_rule_regional" {
  count       = var.waf_regional && var.create_rules == "true" ? 1 : 0
  name        = "WAFIncludesRule"
  metric_name = "WAFIncludesRule"

  predicate {
    data_id = aws_wafregional_byte_match_set.byte_set_includes_regional.0.id
    negated = false
    type    = "ByteMatch"
  }
}

##### OWASP 10: IP Blacklist #####

resource "aws_waf_ipset" "ipset_blacklist_global" {
  count = var.waf_global && var.create_rules == "true" ? 1 : 0
  name  = "ipset_blacklist"

  ip_set_descriptors {
    type  = "IPV4"
    value = var.cidr_blacklist1
  }

  ip_set_descriptors {
    type  = "IPV4"
    value = var.cidr_blacklist2
  }

  ip_set_descriptors {
    type  = "IPV4"
    value = var.cidr_blacklist3
  }

  ip_set_descriptors {
    type  = "IPV4"
    value = var.cidr_blacklist4
  }

  ip_set_descriptors {
    type  = "IPV4"
    value = var.cidr_blacklist5
  }
}

resource "aws_wafregional_ipset" "ipset_blacklist_regional" {
  count = var.waf_regional && var.create_rules == "true" ? 1 : 0
  name  = "ipset_admin"

  ip_set_descriptor {
    type  = "IPV4"
    value = var.cidr_blacklist1
  }

  ip_set_descriptor {
    type  = "IPV4"
    value = var.cidr_blacklist2
  }

  ip_set_descriptor {
    type  = "IPV4"
    value = var.cidr_blacklist3
  }

  ip_set_descriptor {
    type  = "IPV4"
    value = var.cidr_blacklist4
  }

  ip_set_descriptor {
    type  = "IPV4"
    value = var.cidr_blacklist5
  }
}

resource "aws_waf_rule" "waf_blacklist_rule_global" {
  count       = var.waf_global && var.create_rules == "true" ? 1 : 0
  name        = "WAFBlacklistRule"
  metric_name = "WAFBlacklistRule"

  predicates {
    data_id = aws_waf_ipset.ipset_blacklist_global.0.id
    negated = false
    type    = "IPMatch"
  }
}

resource "aws_wafregional_rule" "waf_blacklist_rule_regional" {
  count       = var.waf_regional && var.create_rules == "true" ? 1 : 0
  name        = "WAFBlacklistRule"
  metric_name = "WAFBlacklistRule"

  predicate {
    data_id = aws_wafregional_ipset.ipset_blacklist_regional.0.id
    negated = false
    type    = "IPMatch"
  }
}

##### WAF ACL with OWASP 10 rules #####

resource "aws_waf_web_acl" "waf_acl_owasp10_global" {
  count       = var.waf_global && var.create_rules == "true" ? 1 : 0
  name        = var.waf_acl_name
  metric_name = var.waf_metric_name

  default_action {
    type = "ALLOW"
  }

  rules {
    action {
      type = var.rules_action
    }

    priority = 10
    rule_id  = aws_waf_rule.waf_size_rule_global.0.id
    type     = "REGULAR"
  }

  rules {
    action {
      type = var.rules_action
    }

    priority = 20
    rule_id  = aws_waf_rule.waf_blacklist_rule_global.0.id
    type     = "REGULAR"
  }

  rules {
    action {
      type = var.rules_action
    }

    priority = 30
    rule_id  = aws_waf_rule.waf_jwt_rule_global.0.id
    type     = "REGULAR"
  }

  rules {
    action {
      type = var.rules_action
    }

    priority = 40
    rule_id  = aws_waf_rule.waf_sql_rule_global.0.id
    type     = "REGULAR"
  }

  rules {
    action {
      type = var.rules_action
    }

    priority = 50
    rule_id  = aws_waf_rule.waf_xss_rule_global.0.id
    type     = "REGULAR"
  }

  rules {
    action {
      type = var.rules_action
    }

    priority = 60
    rule_id  = aws_waf_rule.waf_path_rule_global.0.id
    type     = "REGULAR"
  }

  rules {
    action {
      type = var.rules_action
    }

    priority = 70
    rule_id  = aws_waf_rule.waf_php_rule_global.0.id
    type     = "REGULAR"
  }

  rules {
    action {
      type = var.rules_action
    }

    priority = 80
    rule_id  = aws_waf_rule.waf_csrf_rule_global.0.id
    type     = "REGULAR"
  }

  rules {
    action {
      type = var.rules_action
    }

    priority = 90
    rule_id  = aws_waf_rule.waf_includes_rule_global.0.id
    type     = "REGULAR"
  }

  rules {
    action {
      type = var.rules_action
    }

    priority = 100
    rule_id  = aws_waf_rule.waf_admin_rule_global.0.id
    type     = "REGULAR"
  }

  tags = merge(var.tags, local.tags)
}

resource "aws_wafregional_web_acl" "waf_acl_owasp10_regional" {
  count       = var.waf_regional && var.create_rules == "true" ? 1 : 0
  name        = var.waf_acl_name
  metric_name = var.waf_metric_name

  default_action {
    type = "ALLOW"
  }

  rule {
    action {
      type = var.rules_action
    }

    priority = 10
    rule_id  = aws_wafregional_rule.waf_size_rule_regional.0.id
    type     = "REGULAR"
  }

  rule {
    action {
      type = var.rules_action
    }

    priority = 20
    rule_id  = aws_wafregional_rule.waf_blacklist_rule_regional.0.id
    type     = "REGULAR"
  }

  rule {
    action {
      type = var.rules_action
    }

    priority = 30
    rule_id  = aws_wafregional_rule.waf_jwt_rule_regional.0.id
    type     = "REGULAR"
  }

  rule {
    action {
      type = var.rules_action
    }

    priority = 40
    rule_id  = aws_wafregional_rule.waf_sql_rule_regional.0.id
    type     = "REGULAR"
  }

  rule {
    action {
      type = var.rules_action
    }

    priority = 50
    rule_id  = aws_wafregional_rule.waf_xss_rule_regional.0.id
    type     = "REGULAR"
  }

  rule {
    action {
      type = var.rules_action
    }

    priority = 60
    rule_id  = aws_wafregional_rule.waf_path_rule_regional.0.id
    type     = "REGULAR"
  }

  rule {
    action {
      type = var.rules_action
    }

    priority = 70
    rule_id  = aws_wafregional_rule.waf_php_rule_regional.0.id
    type     = "REGULAR"
  }

  rule {
    action {
      type = var.rules_action
    }

    priority = 80
    rule_id  = aws_wafregional_rule.waf_csrf_rule_regional.0.id
    type     = "REGULAR"
  }

  rule {
    action {
      type = var.rules_action
    }

    priority = 90
    rule_id  = aws_wafregional_rule.waf_includes_rule_regional.0.id
    type     = "REGULAR"
  }

  rule {
    action {
      type = var.rules_action
    }

    priority = 100
    rule_id  = aws_wafregional_rule.waf_admin_rule_regional.0.id
    type     = "REGULAR"
  }

  tags = merge(var.tags, local.tags)
}

##### Web ACL without rules #####

resource "aws_waf_web_acl" "waf_acl_global" {
  count       = var.waf_global && var.create_rules == "false" ? 1 : 0
  name        = var.waf_acl_name
  metric_name = var.waf_metric_name

  default_action {
    type = "ALLOW"
  }

  tags = merge(var.tags, local.tags)
}

resource "aws_wafregional_web_acl" "waf_acl_regional" {
  count       = var.waf_regional && var.create_rules == "false" ? 1 : 0
  name        = var.waf_acl_name
  metric_name = var.waf_metric_name

  default_action {
    type = "ALLOW"
  }

  tags = merge(var.tags, local.tags)
}
