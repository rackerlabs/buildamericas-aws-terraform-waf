variable "admin_cidr" {
  description = "Admin CIDR allowed"
  type        = string
  default     = "127.0.0.1/32"
}

variable "admin_path" {
  description = "Admin URL Path"
  type        = string
  default     = "/admin"
}

variable "cidr_blacklist1" {
  description = "CIDR blacklisted 1"
  type        = string
  default     = "10.0.0.0/8"
}

variable "cidr_blacklist2" {
  description = "CIDR blacklisted 2"
  type        = string
  default     = "192.168.0.0/16"
}

variable "cidr_blacklist3" {
  description = "CIDR blacklisted 3"
  type        = string
  default     = "169.254.0.0/16"
}

variable "cidr_blacklist4" {
  description = "CIDR blacklisted 4"
  type        = string
  default     = "172.16.0.0/16"
}

variable "cidr_blacklist5" {
  description = "CIDR blacklisted 5"
  type        = string
  default     = "127.0.0.1/32"
}

variable "waf_acl_name" {
  description = "WAF ACL name"
  type        = string
  default     = "WAF-ACL"
}

variable "waf_metric_name" {
  description = "WAF ACL metric name (Alphanumeric characters only)"
  type        = string
  default     = "WAFACL"
}

variable "rules_action" {
  description = "Action taken on each rule (BLOCK or COUNT)"
  type        = string
  default     = "COUNT"
}

variable "waf_global" {
  description = "Is WAF Global resource (Cloudfront usage)"
  type        = bool
  default     = false
}

variable "waf_regional" {
  description = "Is WAF Regional resource (ALB and/or API Gateway Stage usage)"
  type        = bool
  default     = false
}

variable "create_rules" {
  description = "Option to create WAF rules"
  type        = string
  default     = "false"
}

variable "tags" {
  description = "Custom tags to apply to all resources."
  type        = map(string)
  default     = {}
}

variable "environment" {
  description = "Build environment"
  type        = string
  default     = "Development"
}
