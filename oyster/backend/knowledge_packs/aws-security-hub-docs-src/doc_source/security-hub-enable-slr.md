<!-- source: https://github.com/awsdocs/aws-security-hub-user-guide/blob/47bfe2f1de2e486914543113d2e751f3e2ed8868/doc_source/security-hub-enable-slr.md -->
# Service\-linked role assigned to Security Hub<a name="security-hub-enable-slr"></a>

When you enable Security Hub, it is assigned a service\-linked role named `AWSServiceRoleForSecurityHub`\. This service\-linked role includes the permissions and trust policy that Security Hub requires to do the following:
+ Detect and aggregate findings from Amazon GuardDuty, Amazon Inspector, and Amazon Macie
+ Configure the requisite AWS Config infrastructure to run security checks for the supported standards \(in this release, CIS AWS Foundations\)

To view the details of `AWSServiceRoleForSecurityHub`, on the **Settings** page, choose **General** and then **View service permissions**\. For more information, see [Using service\-linked roles for AWS Security Hub](using-service-linked-roles.md)\.

For more information about service\-linked roles, see [Using service\-linked roles](https://docs.aws.amazon.com/IAM/latest/UserGuide/using-service-linked-roles.html) in the *IAM User Guide*\.