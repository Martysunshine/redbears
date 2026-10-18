<!-- source: https://github.com/awsdocs/iam-user-guide/blob/e2b8637a825b9f292bb04af61277d067dfcc5676/doc_source/reference_policies_examples_iam_policy-sim-path.md -->
# IAM: Access the policy simulator API based on user path<a name="reference_policies_examples_iam_policy-sim-path"></a>

This example shows how you might create an identity\-based policy that allows using the policy simulator API only for those users that have the path `Department/Development`\. This policy grants the permissions necessary to complete this action programmatically from the AWS API or AWS CLI\. To use this policy, replace the *italicized placeholder text* in the example policy with your own information\. Then, follow the directions in [create a policy](access_policies_create.md) or [edit a policy](access_policies_manage-edit.md)\.

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "iam:GetContextKeysForPrincipalPolicy",
                "iam:SimulatePrincipalPolicy"
            ],
            "Effect": "Allow",
            "Resource": "arn:aws:iam::*:user/Department/Development/*"
        }
    ]
}
```

**Note**  
To create a policy that allows using the policy simulator console for those users that have the path `Department/Development`, see [IAM: Access the policy simulator console based on user path](reference_policies_examples_iam_policy-sim-path-console.md)\.