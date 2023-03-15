# Challenges
- Learn Terraform
- Identify the options on how to get the necesarry events
- Finding how to find all necesarry data to make the right desicions to remediate or not

# Events used
- `RunInstances`
  New instanec is started
- `AuthorizeSecurityGroupIngress` 
  Ingress rules added
- `ModifyNetworkInterfaceAttribute`
  Find if a security group is added to a interface

# Scope not implemented 
- Make sure the SG at least is attached to one instance
- Public subnet / public IP check
- Lacks proper testing to find possible edge cases / race conditions

# Considerations
Selected to use CloudTrail instead of AWS Config to monitor for changes, even if AWS says Config is the feature.  CloudTrail events can take around 15 minutes so they will always be a little out of sync.  
I have not enabled AWS Config in my private playground AWS account and experience have learned me that it is cumbersome to disable again. While the cloudtrail events already are available.


# Useful Terraform commands for a Terraform noob
- `terraform init`
- `terraform plan`
- `terraform apply`
- `terraform destroy`


# Possible Improvements
- Splitting the terraform into multiple templates/modules
- Handling of Terraform State shared storage
- Adding outputs to the terraform to make debugging easier
- Multiple regions support
- Error handling, retry, etc
- Better logging with help of a logger 
- CI / CD
- Automated Tests
- Configuration to support different environments, etc
- Set permission boundary for the role
- IPv6 check also
- Replace all usage of magic strings
- Clean up code


# Possible other implementation options to get/manage the events
- EventBridge
- AWS config


# Sources
- https://developer.hashicorp.com/terraform/tutorials/aws-get-started
- https://aws.amazon.com/blogs/security/how-to-monitor-aws-account-configuration-changes-and-api-calls-to-amazon-ec2-security-groups/
- https://aws.amazon.com/premiumsupport/knowledge-center/cloudtrail-event-history-changed/