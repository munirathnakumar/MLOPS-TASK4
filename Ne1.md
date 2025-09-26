### Part 2 of 2: Targeted RBAC Validation & Conclusion

---

### **5. Targeted RBAC Validation**

This section details a targeted, two-part validation of Entra ID and Azure RBAC built-in roles.

#### **5.1 Entra ID Roles (User Assignment & Scoping)**

We will validate the most critical roles by auditing user assignments and then testing their core functionality. The validation is performed by a user with the **Role Management Administrator** and **Directory Readers** roles.

**Automated User Assignment Extraction:**
We will use a PowerShell script to extract all user-to-role assignments for a data-driven audit. This provides an authoritative list for top management.

```powershell
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

