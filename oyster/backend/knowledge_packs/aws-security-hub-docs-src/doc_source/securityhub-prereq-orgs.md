<!-- source: https://github.com/awsdocs/aws-security-hub-user-guide/blob/47bfe2f1de2e486914543113d2e751f3e2ed8868/doc_source/securityhub-prereq-orgs.md -->
# Using AWS Organizations to manage accounts<a name="securityhub-prereq-orgs"></a>

To help automate and streamline the management of accounts, Security Hub strongly recommends that you enable AWS Organizations\.

If you have Organizations enabled, then Security Hub automatically detects new accounts as they are added to your organization\.

For information about setting up Organizations, see [Creating and managing an organization](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_org.html) in the *AWS Organizations User Guide*\.

After you set up your organization, your organization management account designates the Security Hub administrator account\. See [Designating a Security Hub administrator account](designate-orgs-admin-account.md)\. The Security Hub administrator account is also the delegated administrator account in Organizations\.

The Security Hub administrator account then enables and manages other organization accounts as Security Hub member accounts\. For more information, see [Managing member accounts that belong to an organization](securityhub-accounts-orgs.md)\.