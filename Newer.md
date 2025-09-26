1. Executive Summary
This document provides a comprehensive security validation playbook for our Microsoft 365 environment's security baseline. The objective is to confirm that our security controls are effective and that user permissions adhere to the principle of least privilege. This is a rigorous, production-grade process that ensures our environment is secure against common threats.
Our approach includes a detailed review of Conditional Access policies, data protection controls, and a targeted validation of both Entra ID and Azure RBAC built-in roles. To ensure an efficient and data-driven process, we will utilize automation scripts to extract user assignments for auditing and provide all findings in a clear, actionable format.
2. Validation Strategy & Scope
The validation strategy is two-fold: a foundational controls validation and a targeted RBAC validation.
 * Foundational Controls Validation: A granular, step-by-step test of core policies that protect our identities, data, and devices. This section confirms that our security configurations are actively working as intended.
 * Targeted RBAC Validation: Instead of an exhaustive test of every built-in role's permissions, we will validate the most critical security principle: least privilege. We will perform a user assignment audit and conduct functional tests to confirm the separation of duties is enforced.
3. Resources Required
To conduct this validation in a controlled and auditable manner, the following resources are required:
| Resource Type | Description |
|---|---|
| Privileged Accounts | Global Admin: For configuring and validating tenant-wide settings. <br> User Admin: For testing limited administrative functions. <br> Security Admin: For validating security-specific controls like Defender and Purview. |
| Standard Accounts | Project User: A cloud-only user for end-user policy testing (DLP, CA). <br> External Guest User: An external email for negative testing of guest access. |
| Test Devices | Managed Laptop: A corporate device enrolled in Intune. <br> Unmanaged Laptop: A personal device for testing denied access. |
| Tooling & Portals | Access to Entra Admin Center, Azure Portal, Purview, Defender, and a PowerShell environment with the Microsoft.Graph and Az modules. |
4. Foundational Controls Validation
This section details the step-by-step validation of our core security baseline controls.
| Control ID | Control Description | Validation Steps (Granular) | Expected Result | Evidence to Capture |
|---|---|---|---|---|
| CA1-CA6 | Conditional Access Policies | 1. As Global Admin, attempt to sign in to Entra and reject the MFA request. 2. As Project User, approve the MFA request to sign in to Office. 3. On the unmanaged laptop, configure a legacy mail client with the Project User's credentials and try to connect. 4. On the unmanaged laptop, attempt to sign in from a home network. | 1. Sign-in is denied. 2. Sign-in succeeds. 3. Connection is blocked. 4. Sign-in is blocked. All denied attempts should be logged in Entra sign-in logs with the correct CA policy name. | Screenshots of denied access messages. Exported Entra sign-in logs showing policy enforcement. |
| AC1-AC2 | Account Restrictions | 1. As Global Admin, review Project User's properties to confirm OnPremisesSyncEnabled is False. 2. Attempt to invite Guest User to a Teams team. | 1. The user is a cloud-only account. 2. The invitation is blocked. | Screenshot of the user property and the invitation failure message. |
| PW1 | Password Policy | As Project User, attempt to change the password to a simple or common one. | The password change is rejected, and a message cites a violation of password complexity rules. | Screenshot of the password rejection message. |
| DV1 | Device Compliance | As Project User, on the unmanaged laptop, attempt to access a file on a SharePoint site protected by a "Require compliant device" policy. | Access is denied, and the Entra sign-in logs show the device was not compliant. | Screenshot of the denied access message. |
| TL1-TL4 | Tooling Configuration | 1. Defender: As Global Admin, go to https://security.microsoft.com and verify the dashboard is active. 2. Safe Links: Send a test URL to Project User in Teams and click it. 3. Auditing: Perform a user action (e.g., file creation) and then search for the event in the Purview audit log. | 1. The dashboard is active. 2. The URL is rewritten. 3. The user action is logged. | Screenshots of the Defender dashboard, the rewritten URL, and the audit log entry. |
| IP1-DLP2 | Data & Info Protection | 1. Labels: As Project User, create a new file; the "Restricted" label is applied by default. Attempt to downgrade a "Confidential" file to "Public." 2. DLP: Create a document with test credit card numbers and attempt to email it to Guest User. | 1. The default label is applied. Downgrade is blocked. 2. The email is blocked, and a DLP incident is logged in Purview. | Screenshots of the automatic label and the blocked downgrade. A screenshot of the DLP incident report. |
| DLM1 | Data Lifecycle Management | As Global Admin, review the retention policies in https://compliance.microsoft.com. | A 15-year retention policy is correctly scoped to all target services (Exchange, SharePoint, Teams, M365 Groups). | Screenshot of the retention policy configuration. |
5. Targeted RBAC Validation
This section details a targeted, two-part validation of Entra ID and Azure RBAC built-in roles.
5.1 Entra ID Roles (User Assignment & Scoping)
We will validate the most critical roles by auditing user assignments and then testing their core functionality. The validation is performed by a user with the Role Management Administrator and Directory Readers roles.
Automated User Assignment Extraction:
We will use a PowerShell script to extract all user-to-role assignments for a data-driven audit. This provides an authoritative list for top management.
# Connect to Microsoft Graph with required scopes
Connect-MgGraph -Scopes "RoleManagement.Read.Directory", "Directory.Read.All"

# Get all built-in Entra ID roles and their members
$allAssignments = @()
$roles = Get-MgDirectoryRole | Where-Object { $_.RoleTemplateId -ne $null }
foreach ($role in $roles) {
    Write-Host "Extracting members for role: $($role.DisplayName)"
    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
    foreach ($member in $members) {
        $allAssignments += [PSCustomObject]@{
            RoleName = $role.DisplayName
            UserPrincipalName = $member.UserPrincipalName
            DisplayName = $member.DisplayName
        }
    }
}
# Export the data to a CSV file for review
$allAssignments | Export-Csv -Path "EntraID_RoleAssignments_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation

User-Based Validation:
After the export, a manual audit of the CSV will confirm that only authorized users have roles. We will then perform the following functional tests to validate the core principle of least privilege.
| Role to Validate | Validation Steps | Expected Result | Evidence to Capture |
|---|---|---|---|
| Global Admin | 1. Sign in as Global Admin. 2. Attempt a highly privileged task, like deleting an administrative user or modifying Conditional Access policies. | All actions succeed. | Screenshot of the successful action. Audit log entry confirming the action. |
| User Admin | 1. Sign in as User Admin. 2. Attempt to create a user. 3. Attempt to access Conditional Access policies. | The user creation succeeds. The privileged task is blocked. | Screenshot of the success and the denied action message. |
| Security Admin | 1. Sign in as Security Admin. 2. Attempt a security task (review Identity Protection). 3. Attempt to perform a user management task (create a user). | The security task succeeds. The user management task is blocked. | Screenshot of both the successful and denied actions. |
5.2 Azure RBAC Roles (User Assignment & Scoping)
We will validate the specified Azure roles to ensure access is scoped correctly and least privilege is enforced. The user running the script needs User Access Administrator or a custom role with Microsoft.Authorization/roleAssignments/read permission.
Automated User Assignment Extraction:
We will use the Azure CLI to extract a clear list of role assignments at the subscription level for review.
# Get all role assignments at the subscription level
az role assignment list --subscription "<Your-Subscription-ID>" --all --output json > azure_rbac_assignments_$(date +%Y%m%d).json

User-Based Validation:
We will use a test Resource Group to validate the core functions of each role.
| Role to Validate | Validation Steps | Expected Result | Evidence to Capture |
|---|---|---|---|
| Owner | 1. Assign the Owner role to a test user on a Resource Group. 2. As the test user, create a new virtual machine. 3. Assign a Contributor role to another user within that Resource Group. | Both actions succeed. | Azure Activity Log entry showing both actions succeeded. |
| Contributor | 1. Assign the Contributor role on a Resource Group. 2. As the test user, create a new virtual machine. 3. Attempt to assign the Reader role to another user. | The VM creation succeeds. The role assignment is denied. | Screenshots of the successful VM creation and the "Access Denied" error for role assignment. |
| User Access Admin | 1. Assign the User Access Admin role on a Subscription. 2. As the test user, assign the Reader role on a Resource Group to another user. 3. Attempt to create a new storage account. | The role assignment succeeds. The attempt to create the storage account is denied. | Screenshot of the successful role assignment and the "Access Denied" message for resource creation. |
| Key Vault Roles | 1. Assign Key Vault Reader to one test user and Key Vault Secrets Officer to another. 2. Have both attempt to retrieve a secret. | The Reader is denied from viewing the secret value. The Secrets Officer successfully retrieves it. | Azure Activity Log entries showing the denied and successful secret retrieval attempts. |
6. Conclusion
This detailed security validation playbook provides a rigorous and auditable process for confirming the effectiveness of our M365 security baseline. The combination of granular functional tests and automated user assignment audits ensures that we not only have the right policies in place but that they are also being correctly enforced. The results of this validation will be compiled into a final report, providing a clear and comprehensive overview of our security posture, complete with evidence and actionable recommendations for any identified vulnerabilities.
This document serves as a foundational component of our ongoing security and compliance efforts, providing confidence to top management that our environment is well-protected.
