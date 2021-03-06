# buildamericas-aws-terraform-waf
This module deploy a WAFv1 module than can contain OWASP10 rules

## Basic Usage
```HCL
module "waf" {
  source = "git@github.com:rackerlabs/buildamericas-aws-terraform-waf//?ref=v0.12.0"
  waf_global   = true
  create_rules = "true"
  waf_acl_name = "generic-owasp-acl"
}
```  
**NOTE**: Only select either waf_global or waf_regional as true to define which type of WAF to create.

## Providers

| Name | Version |
|------|---------|
| aws | >= 2.60.0 |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:-----:|
| admin\_cidr | Admin CIDR allowed | `string` | `"127.0.0.1/32"` | no |
| admin\_path | Admin URL Path | `string` | `"/admin"` | no |
| cidr\_blacklist1 | CIDR blacklisted 1 | `string` | `"10.0.0.0/8"` | no |
| cidr\_blacklist2 | CIDR blacklisted 2 | `string` | `"192.168.0.0/16"` | no |
| cidr\_blacklist3 | CIDR blacklisted 3 | `string` | `"169.254.0.0/16"` | no |
| cidr\_blacklist4 | CIDR blacklisted 4 | `string` | `"172.16.0.0/16"` | no |
| cidr\_blacklist5 | CIDR blacklisted 5 | `string` | `"127.0.0.1/32"` | no |
| create\_rules | Option to create WAF rules | `string` | `"false"` | no |
| environment | Build environment | `string` | `"Development"` | no |
| rules\_action | Action taken on each rule (BLOCK or COUNT) | `string` | `"COUNT"` | no |
| tags | Custom tags to apply to all resources. | `map(string)` | `{}` | no |
| waf\_acl\_name | WAF ACL name | `string` | `"WAF-ACL"` | no |
| waf\_global | Is WAF Global resource (Cloudfront usage) | `bool` | `false` | no |
| waf\_metric\_name | WAF ACL metric name (Alphanumeric characters only) | `string` | `"WAFACL"` | no |
| waf\_regional | Is WAF Regional resource (ALB and/or API Gateway Stage usage) | `bool` | `false` | no |

## Outputs

| Name | Description |
|------|-------------|
| waf\_acl\_arn | WAF ACL ARN |
| waf\_acl\_id | WAF ACL ID |

