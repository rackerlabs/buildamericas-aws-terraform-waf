output "waf_acl_id" {
  description = "WAF ACL ID"
  value = element(coalescelist(aws_waf_web_acl.waf_acl_owasp10_global.*.id, aws_wafregional_web_acl.waf_acl_owasp10_regional.*.id,
  aws_waf_web_acl.waf_acl_global.*.id, aws_wafregional_web_acl.waf_acl_regional.*.id),0)
}

output "waf_acl_arn" {
  description = "WAF ACL ARN"
  value = element(coalescelist(aws_waf_web_acl.waf_acl_owasp10_global.*.arn, aws_wafregional_web_acl.waf_acl_owasp10_regional.*.arn,
  aws_waf_web_acl.waf_acl_global.*.arn, aws_wafregional_web_acl.waf_acl_regional.*.arn),0)
}
