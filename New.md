Perfect ✅
I’ll print the entire document in one go in the expanded style (strategy → resources → detailed control validation → evidence → conclusion).

This will be long, but it will cover all controls (CA1–CA6, AC1–AC2, PW1, DV1, TL1–TL4, IP1–IP3, DLP1–DLP2, DLM1, R1–R2).

⸻

Baseline Security Validation – Final Expanded Playbook

⸻

1. Strategy

The objective of this playbook is to validate that baseline security controls for Microsoft 365, Entra ID, and Azure RBAC are properly enforced across the corporate environment.

The validation scope includes:
	•	Conditional Access policies (CA1–CA6)
	•	Identity restrictions (AC1–AC2)
	•	Password policies (PW1)
	•	Device compliance requirements (DV1)
	•	Tooling configurations (TL1–TL4)
	•	Information protection (IP1–IP3)
	•	Data Loss Prevention (DLP1–DLP2)
	•	Data Lifecycle Management (DLM1)
	•	Role-based access validation (R1–R2)

Principles applied:
	•	Least privilege: Only built-in Entra ID and Azure RBAC roles considered. No workload/application admin actions in scope.
	•	Repeatable validation: URLs, accounts, devices, and tools explicitly listed.
	•	Evidence collection: Screenshots, exported logs, and reports required.
	•	Negative testing: Attempted access from blocked devices, locations, or using legacy auth.

⸻

2. Resources Required

Test Accounts
	•	globaladmin@testtenant.onmicrosoft.com (Global Administrator)
	•	useradmin@testtenant.onmicrosoft.com (User Administrator)
	•	secadmin@testtenant.onmicrosoft.com (Security Administrator)
	•	testuser1@testtenant.onmicrosoft.com (Cloud-only standard user)
	•	guestuser1@externaldomain.com (Guest account, negative test only)

Devices
	•	Corporate-managed Windows 11 laptop enrolled in Intune
	•	Unmanaged/personal laptop (for negative tests only)
	•	Mobile device with Microsoft Authenticator app

Tools / Portals
	•	Entra Admin Center → https://entra.microsoft.com
	•	M365 Admin Center → https://admin.microsoft.com
	•	Azure Portal → https://portal.azure.com
	•	Microsoft Purview → https://compliance.microsoft.com
	•	Defender Security Portal → https://security.microsoft.com
	•	Office apps: Word, Teams, Outlook
	•	PowerShell: Az + MSOnline modules

⸻

3. Control Validation Matrix

Control ID	Control Description	Test Account	Device	Tool/Portal
CA1	Require MFA for Admins	Global Admin	Corporate Laptop	Entra
CA2	Require MFA for Enablement Admins/Users	User Admin, Sec Admin	Corporate Laptop	Entra
CA3	MFA for Cloud Users	TestUser1	Corporate Laptop	Entra
CA4	Risk-Based Conditional Access	TestUser1	Corporate Laptop + VPN	Entra
CA5	Block Legacy Authentication	TestUser1	Unmanaged Laptop	Entra Logs
CA6	Restrict Access to Zscaler IP	TestUser1	Unmanaged Laptop	Entra
AC1	Enforce Cloud-Only Accounts	TestUser1	Corporate Laptop	M365
AC2	Block Guest Access	GuestUser1	Browser	Entra
PW1	Minimum Password Policy	TestUser1	Corporate Laptop	Entra
DV1	Corporate Device Restriction	TestUser1	Unmanaged Laptop	Entra
TL1	Defender for Cloud Enabled	Global Admin	Corporate Laptop	Azure
TL2	Safe Links/Safe Attachments	TestUser1	Teams/Outlook	Defender
TL3	Customer Key Management	Global Admin	Corporate Laptop	Security
TL4	M365 Auditing Enabled	Global Admin	Corporate Laptop	Purview
IP1	Labels for Confidentiality	TestUser1	Word/Teams	Office Apps
IP2	Default Restricted Label	TestUser1	Word	Office Apps
IP3	Prevent Sensitivity Downgrade	TestUser1	Word	Office Apps
DLP1	DLP Blocking for PII	TestUser1	Word/Outlook	Purview
DLP2	Block USB/Bluetooth	TestUser1	Corporate Laptop	Device Manager
DLM1	Retention Policy 15 Years	Global Admin	Purview	Compliance
R1	Entra Role Validation	Global Admin, User Admin, Sec Admin	Corporate Laptop	Entra
R2	Azure RBAC Role Validation	Global Admin, TestUser1	Corporate Laptop	Azure


⸻

4. Detailed Control Validations

⸻

CA1 – Require MFA for Admins

Objective: Ensure all administrator accounts require MFA.

Resources:
	•	Account: globaladmin@testtenant.onmicrosoft.com
	•	Device: Corporate laptop
	•	Tool: Entra Admin Center

Steps:
	1.	Open InPrivate browser → https://portal.office.com.
	2.	Log in as Global Admin.
	3.	System requests MFA (Authenticator app).
	4.	Reject MFA → login denied.
	5.	Retry and Approve MFA → login allowed.
	6.	In Entra → Sign-in Logs → filter Global Admin.
	7.	Confirm “MFA Required & Satisfied” recorded.

Expected Result: Admin accounts cannot access without MFA.

Evidence: Screenshot of sign-in logs.

⸻

CA2 – Require MFA for Enablement Admins/Users

Objective: Confirm User Admin and Security Admin roles enforce MFA.

Steps:
	1.	Login with useradmin@testtenant → MFA triggered.
	2.	Reject → denied. Approve → access granted.
	3.	Repeat with secadmin@testtenant.
	4.	Verify logs in Entra.

Expected Result: All enablement/admin roles enforce MFA.

⸻

CA3 – MFA for Cloud Users

Objective: Validate cloud users are MFA protected.

Steps:
	1.	Login with testuser1@testtenant.
	2.	MFA challenge prompted.
	3.	Approve → success. Reject → denied.
	4.	Verify via Entra sign-in logs.

Expected Result: Cloud-only users require MFA.

⸻

CA4 – Risk-Based Conditional Access

Objective: Verify access blocked when login risk is elevated.

Steps:
	1.	Connect via VPN from risky geo-IP (e.g., anonymizer).
	2.	Login with TestUser1.
	3.	Expect “Access blocked due to risk policy.”
	4.	In Entra → Identity Protection → check risky sign-ins.

Expected Result: High-risk logins denied.

⸻

CA5 – Block Legacy Authentication

Objective: Ensure legacy auth is blocked.

Steps:
	1.	From unmanaged laptop, configure Outlook 2010 profile for TestUser1.
	2.	Attempt login → fails (due to legacy auth block).
	3.	Entra Sign-in Logs → filter client app → “Legacy Authentication.”

Expected Result: Legacy authentication denied.

⸻

CA6 – Restrict Access to Zscaler IP

Objective: Validate login allowed only from corporate Zscaler egress.

Steps:
	1.	Connect unmanaged laptop on home Wi-Fi.
	2.	Login with TestUser1 → denied (“Blocked by location policy”).
	3.	Retry from corporate laptop routed via Zscaler → allowed.

Expected Result: Access restricted to Zscaler IPs.

⸻

AC1 – Enforce Cloud-Only Accounts

Objective: Verify that only cloud accounts are allowed.

Steps:
	1.	Try creating a federated/AD account in Entra.
	2.	Attempt login → denied.
	3.	Only *.onmicrosoft.com accounts functional.

Expected Result: Only cloud-only accounts permitted.

⸻

AC2 – Block Guest Access

Objective: Validate guest users are denied login.

Steps:
	1.	Login as guestuser1@externaldomain.com.
	2.	Attempt portal access → denied.
	3.	Entra Logs → “Guest access blocked.”

Expected Result: Guest accounts cannot sign in.

⸻

PW1 – Minimum Password Policy

Objective: Confirm password complexity enforced.

Steps:
	1.	Login as TestUser1 → attempt password reset.
	2.	Enter weak password (e.g., Password1) → rejected.
	3.	Enter strong password (length + complexity) → accepted.

Expected Result: Weak passwords not allowed.

⸻

DV1 – Corporate Device Restriction

Objective: Verify access restricted to compliant devices.

Steps:
	1.	From unmanaged laptop, login as TestUser1 → denied.
	2.	From corporate laptop (Intune-enrolled), login succeeds.

Expected Result: Only compliant devices allowed.

⸻

TL1 – Defender for Cloud Enabled

Objective: Ensure Defender for Cloud baseline enabled.

Steps:
	1.	Login Azure → Defender for Cloud.
	2.	Verify “Microsoft Defender for Cloud Plan” enabled.

Expected Result: Defender baseline policies enforced.

⸻

TL2 – Safe Links & Attachments

Objective: Validate Safe Links/Attachments.

Steps:
	1.	Send malicious test link to TestUser1 in Teams.
	2.	Click → redirected to warning page.
	3.	Send test malware file → blocked.

Expected Result: Malicious links/files blocked.

⸻

TL3 – Customer Key Management

Objective: Validate customer keys in use.

Steps:
	1.	In Security & Compliance → check key configuration.
	2.	Confirm keys issued by organization.

Expected Result: Customer keys visible and applied.

⸻

TL4 – M365 Auditing Enabled

Objective: Validate unified audit logging.

Steps:
	1.	In Purview → Audit → verify “Audit Enabled.”
	2.	Perform activity (e.g., file download).
	3.	Confirm activity logged.

Expected Result: Unified auditing enabled and functional.

⸻

IP1 – Labels for Confidentiality

Objective: Validate sensitivity labels.

Steps:
	1.	Open Word → save doc → apply “Confidential” label.
	2.	File metadata updated with label.

Expected Result: Confidentiality labels applied.

⸻

IP2 – Default Restricted Label

Objective: Ensure default restricted label applied.

Steps:
	1.	Create new document without applying label.
	2.	Save → system applies default “Restricted.”

Expected Result: Default label enforced.

⸻

IP3 – Prevent Sensitivity Downgrade

Objective: Ensure downgrade restricted.

Steps:
	1.	Open Confidential doc.
	2.	Attempt to downgrade to Public → denied.

Expected Result: Sensitivity downgrade prevented.

⸻

DLP1 – DLP Blocking for PII

Objective: Validate DLP policies.

Steps:
	1.	Create doc with sample SSN.
	2.	Attempt to share via Outlook → blocked.

Expected Result: DLP policy blocks PII sharing.

⸻

DLP2 – Block USB/Bluetooth

Objective: Ensure removable media blocked.

Steps:
	1.	Connect USB on corporate laptop.
	2.	Attempt file copy → blocked.
	3.	Attempt Bluetooth transfer → blocked.

Expected Result: Removable storage blocked.

⸻

DLM1 – Retention Policy 15 Years

Objective: Validate retention policy.

Steps:
	1.	In Purview → Retention Policies.
	2.	Verify mail/doc retention set to 15 years.

Expected Result: Retention applied per baseline.

⸻

R1 – Entra Role Validation

Objective: Validate Entra built-in roles (Global, User, Security Admin).

Steps:
	1.	Login as Global Admin → full access to tenant settings.
	2.	Login as User Admin → can reset passwords, create users, no access to CA.
	3.	Login as Security Admin → can access security dashboards, no user management.

Expected Result: Roles scoped to least privilege.

⸻

R2 – Azure RBAC Role Validation

Objective: Validate Azure RBAC built-in roles.

Steps:
	1.	Assign Reader to TestUser1 → login Azure → read-only access confirmed.
	2.	Assign Contributor → can create resources, cannot assign roles.
	3.	Assign Owner → full access including RBAC assignments.

Expected Result: Built-in RBAC roles work per Microsoft scope.

⸻

5. Evidence Collection Format

Each test must capture evidence in the following template:
	•	Control ID: (e.g., CA1)
	•	Control Description: (e.g., Require MFA for Admins)
	•	Test Performed: (step summary)
	•	Evidence: (screenshot/log export/file path)
	•	Status: Pass/Fail

Example:

Control ID: CA1
Description: Require MFA for Admins
Test Performed: Logged in with Global Admin, MFA enforced, login failed when denied, succeeded when approved.
Evidence: Screenshot - Entra Sign-in Logs (showing MFA required and satisfied).
Status: Pass


⸻

6. Conclusion

All baseline security controls across Microsoft 365, Entra ID, and Azure RBAC have been validated using corporate accounts, compliant devices, and built-in roles.
	•	MFA: Enforced for admins and users, including risk-based policies.
	•	Access Controls: Guests, legacy auth, and unmanaged devices blocked.
	•	Tooling: Defender, auditing, and customer key baselines in place.
	•	Information Protection: Labels, restrictions, and DLP applied.
	•	Lifecycle Management: Retention policies aligned with compliance.
	•	Role Validation: Entra ID and Azure RBAC roles provide correct least-privilege access.

Next Actions:
	•	Archive evidence reports into compliance repository.
	•	Review quarterly to confirm policies are still enforced.
	•	Integrate into continuous compliance monitoring (e.g., Microsoft Defender for Cloud recommendations).

⸻

✅ This is the final detailed document in screen output.

Do you want me to now convert this into Markdown format (so you can use it directly in your repo/SharePoint/Confluence)?


Great — I tightened and fully expanded the role-assignment validation, added exact UI navigation, and included multiple command / automation options (PowerShell, Azure CLI, Microsoft Graph) so you — or a tester — can run the checks and collect strong, auditable evidence. I also filled in any missing URL and tool details for other controls where previously loose.

Below is the final production-grade playbook printed on screen in Markdown-style. It contains:
	•	Strategy, scope and test resources
	•	Complete control validation (all controls CA1→DLM1) with exact UI steps, URLs and expected results — corrected to use corporate devices for MFA tests and unmanaged devices only for negative cases
	•	Thorough Entra ID role assignment validation: UI steps, PowerShell (AzureAD + Microsoft Graph), Graph API examples, what to export, evidence to collect, acceptance criteria and remediation actions
	•	Azure RBAC role assignment validation: UI + Azure CLI + PowerShell examples, activity log checks
	•	Evidence capture format, CSV headers and example queries
	•	Remediation / acceptance criteria and a short conclusion

⸻

Baseline Security Validation — Final Expanded Playbook

Note: perform all positive tests using the corporate-managed device (Intune enrolled). Use unmanaged/personal device only where a negative test requires showing an access block (legacy auth, location block).

⸻

1. Strategy & Scope

Objective: Validate baseline controls for Microsoft 365, Entra ID and Azure RBAC are correctly configured and enforced.

Scope:
	•	Conditional Access (CA1–CA6)
	•	Accounts: Cloud-only and Guest restrictions (AC1–AC2)
	•	Password policy (PW1)
	•	Device compliance (DV1)
	•	Tooling: Defender, Safe Links/Attachments, Customer Key, Auditing (TL1–TL4)
	•	Information Protection (IP1–IP3)
	•	Data Loss Prevention (DLP1–DLP2)
	•	Data Lifecycle Management (DLM1)
	•	Role validation limited to role assignment & least privilege for Entra built-in roles and Azure RBAC built-in roles (R1, R2). No workload-level admin tests.

Deliverables: Detailed test steps, expected results, evidence items (screenshots, exported CSVs, log IDs), remediation recommendations.

⸻

2. Resources Required

Test accounts (create prior to testing):
	•	globaladmin@yourtenant.onmicrosoft.com — Global Administrator
	•	secadmin@yourtenant.onmicrosoft.com — Security Administrator
	•	useradmin@yourtenant.onmicrosoft.com — User Administrator
	•	testuser1@yourtenant.onmicrosoft.com — Cloud-only user (standard)
	•	guestuser1@external.com — External guest (negative test)

Devices:
	•	Corporate-managed laptop (Windows 11, Intune enrolled) — primary testing device
	•	Unmanaged/personal laptop — only for negative tests (legacy auth, location)

Tools & Portals:
	•	Entra Admin Center — https://entra.microsoft.com (Roles & administrators, Sign-ins, Audit logs, Conditional Access)
	•	Azure Portal — https://portal.azure.com (Privileged Identity Management, Activity Log, Key Vaults, IAM)
	•	Microsoft 365 Admin Center — https://admin.microsoft.com
	•	Microsoft Purview / Compliance — https://compliance.microsoft.com
	•	Microsoft Defender Security portal — https://security.microsoft.com
	•	PowerShell (Microsoft.Graph, AzureAD or AzureAD.Standard.Preview modules), Azure CLI (az)
	•	Microsoft Graph API (Graph Explorer or REST calls)

⸻

3. Executive Control Matrix (quick view)

(Kept as previously delivered — omitted here for brevity; full matrix is in the large document you already accepted.)

⸻

4. Detailed Control Validation (full expanded)

Each control below shows: Objective → Resources → Step-by-step (UI and tooling) → Expected result → Evidence to capture.

⸻

CA1 — Require MFA for Administrators

Objective: Verify MFA enforcement for admin roles.

Resources: globaladmin@... and secadmin@..., corporate laptop, Microsoft Authenticator mobile.

UI Steps (recommended, corporate device):
	1.	Open InPrivate / Incognito browser on corporate laptop.
	2.	Go to https://portal.office.com.
	3.	Sign in as globaladmin@yourtenant.... Enter password.
	4.	Observe the MFA prompt (Authenticator push/verification). Reject push — sign-in must be denied.
	5.	Try again and Approve the push — sign-in must succeed.
	6.	In Entra Admin Center: https://entra.microsoft.com → Monitoring → Sign-ins → filter by globaladmin@.... Open the sign-in entry. Verify:
	•	Conditional Access section shows the policy (name) and Grant controls → mfa or “Require multi-factor authentication”.
	•	Note Timestamp and Request ID.

PowerShell / Automation:
	•	Use Microsoft Graph PowerShell (recommended):

# connect requires consent for RoleManagement.Read.Directory + Directory.Read.All
Connect-MgGraph -Scopes "RoleManagement.Read.Directory","Directory.Read.All","AuditLog.Read.All","Directory.Read.All"
# list sign-ins for user (if using AuditLogs or SignInReports; alternatively use Azure Monitor)
# Sign-ins via MS Graph (requires special privileges) -- using Graph REST:
Invoke-RestMethod -Headers @{ Authorization = "Bearer $token" } -Uri "https://graph.microsoft.com/beta/auditLogs/signIns?\$filter=userDisplayName eq 'globaladmin@yourtenant.onmicrosoft.com'"

Note: Sign-in API may require appropriate permissions and beta endpoint usage.

Expected result: MFA required on every admin sign-in. Sign-in log shows MFA enforcement. Denied attempts recorded when MFA rejected.

Evidence to capture:
	•	Screenshot of MFA prompt.
	•	Screenshot of Entra Sign-in entry (timestamp, Request ID, policy name, MFA result).
	•	Exported sign-in CSV or audit entry with the Request ID.

Acceptance criteria: All admin sign-ins must show CA enforcement for MFA. If any admin sign-in shows “Grant controls = None”, fail and remediate.

⸻

CA2 — Require MFA for Enablement Admins / Microsoft enablement users

Objective: Ensure enablement / service admin accounts (User Admin, Security Admin) require MFA.

Resources: useradmin@..., secadmin@..., corporate laptop.

UI Steps:
	1.	On corporate device, open https://portal.office.com or https://entra.microsoft.com depending on admin console used.
	2.	Sign in as useradmin@.... Observe MFA prompt. Reject → verify denied. Approve → verify access.
	3.	Repeat with secadmin@....
	4.	In Entra → Conditional Access → open the MFA policy targeted at admin roles (verify scope includes Directory roles). Capture policy settings: assignment (Directory roles selected), grant controls.

Expected result: Admin / enablement users must be forced to MFA; CA policy targets directory roles.

Evidence to capture: Screenshot of CA policy settings (targeting Directory roles), sign-in log entries for both test accounts.

⸻

CA3 — Require MFA for M365 cloud users

Objective: Ensure MFA is enforced for standard cloud users.

Resources: testuser1@..., corporate laptop.

Steps (UI):
	1.	On corporate laptop in InPrivate, go to https://portal.office.com.
	2.	Sign in as testuser1@.... Expect MFA prompt; reject → denied; approve → access allowed.
	3.	In Entra → Sign-ins, filter testuser1@... and confirm MFA enforcement: policy name and grant controls.

Expected result: All sign-ins by cloud users are subject to MFA per policy.

Evidence: Sign-in logs, screenshot of MFA prompt, CA policy assignment screenshot.

⸻

CA4 — Risk-based Conditional Access (Identity Protection)

Objective: Verify risky sign-ins trigger conditional access remediation (block or require password reset/MFA).

Resources: testuser1@..., corporate laptop (for controlled simulation), optional VPN to simulate unusual IP.

Steps (UI):
	1.	Connect corporate laptop to a test VPN endpoint in a different country (or use test IP simlation allowed by org rules).
	2.	Go to https://portal.office.com. Sign in as testuser1@....
	3.	If policy blocks high-risk sign-ins, user should be blocked or triggered to perform remediation (e.g., change password) or require MFA.
	4.	As secadmin@..., open Entra → Identity Protection → Risky sign-ins (URL: https://entra.microsoft.com → Security → Identity Protection). Verify recent entry for testuser1@..., examine risk level and remediation action.

Evidence:
	•	Screenshot of Identity Protection entry with risk level and action.
	•	Sign-in log showing CA enforcement (Request ID).

Expected result: High-risk sign-ins handled per policy (blocked or remediated).

⸻

CA5 — Block Legacy Authentication

Objective: Verify legacy authentication (Basic Auth) is blocked.

Resources: testuser1@..., unmanaged laptop with legacy client (Outlook 2010/Thunderbird).

Steps:
	1.	On unmanaged laptop, configure legacy email client (IMAP/POP) for testuser1@....
	2.	Attempt sign-in. It should fail (Basic Auth blocked).
	3.	In Entra → Sign-ins, filter for testuser1@... and Client app = “Other Clients / Legacy Authentication” and confirm failure with CA policy referenced.

Evidence: Sign-in log entry and screenshot of client error.

Expected result: Legacy auth blocked for all accounts; sign-in log shows “legacy authentication blocked” and CA policy name.

⸻

CA6 — Restrict Access to Zscaler Egress IPs (Named Locations)

Objective: Confirm access only allowed from defined Zscaler IP ranges.

Resources: testuser1@..., corporate laptop (Zscaler), unmanaged laptop (home IP).

Steps:
	1.	On corporate laptop (on corporate network routed through Zscaler), sign in to https://portal.office.com as testuser1@... — sign-in should succeed.
	2.	On unmanaged laptop (home ISP), attempt sign-in — sign-in should be blocked by CA.
	3.	In Entra → Named locations: verify Zscaler IP ranges exist and are used in CA policy. (Entra → Security → Conditional Access → Named locations).
	4.	In Entra → Sign-ins, check the blocked login entry; confirm Location matches the external IP and CA decision.

Evidence: Sign-in logs, Named Locations policy screenshot, blocked sign-in screenshot.

Expected result: Only named Zscaler IPs allowed for the CA target group.

⸻

AC1 — Cloud-only Accounts (project users)

Objective: Verify project users use cloud-only authentication (not federated).

Resources: testuser1@... (cloud-only project user), Global Admin.

UI Steps:
	1.	In Entra → Users → open testuser1@... user object. Confirm userType = Member and OnPremisesSyncEnabled = False (indicates cloud-only).
	2.	Attempt to authenticate using federated/hybrid credentials (if available) into the project resources — should fail.

PowerShell (AzureAD module):

Connect-AzureAD
Get-AzureADUser -ObjectId "testuser1@yourtenant.onmicrosoft.com" | Select DisplayName, UserPrincipalName, DirSyncEnabled

Evidence: Screenshot of user object and PowerShell output.

Expected result: Test user reports DirSyncEnabled = False (cloud-only).

⸻

AC2 — Guest Accounts / External Sharing Disabled

Objective: Validate guest invites and guest access are blocked.

Resources: guestuser1@external.com, Global Admin.

UI Steps:
	1.	As Global Admin, go to https://entra.microsoft.com → Users → New guest user → attempt to invite guestuser1@external.com. If tenant setting disallows guest invites, this action should be blocked.
	2.	If the guest already exists, attempt sign-in — expect denial.
	3.	Entra → External Identities → External collaboration settings — confirm “Guests can invite” or “Guest access” toggles are disabled per baseline.

Evidence: Screenshot of blocked invitation or disabled external sharing settings, sign-in log for guest.

Expected result: Guest invites denied and guests cannot access internal resources.

⸻

PW1 — Entra Password Policy (Minimum password complexity & history)

Objective: Verify password policy enforcement.

Resources: testuser1@..., User Admin.

UI Steps:
	1.	As test user, go to https://account.activedirectory.windowsazure.com/PasswordReset (or https://portal.office.com → profile → Change password). Attempt to set a weak password (e.g., Password1). It must be rejected.
	2.	As User Admin or Global Admin, navigate to Entra → Authentication methods (or tenant password protection settings) and confirm policy: Minimum length, complexity, history.

PowerShell:

Connect-AzureAD
(Get-AzureADPolicy -Top 1).DisplayName  # for custom policies, or use Microsoft Graph to query password methods

Evidence: Screenshot of rejected password attempt; screenshot of password policy settings.

Expected result: Weak password attempts rejected; policy applied tenant-wide.

⸻

DV1 — Device Compliance (Intune / K-Work)

Objective: Ensure only compliant devices can access resources.

Resources: Corporate laptop (Intune enrolled), personal laptop.

UI Steps:
	1.	On corporate device, login as testuser1@... to https://portal.office.com — sign-in allowed.
	2.	On non-enrolled personal laptop, attempt sign-in — should be blocked by CA or device compliance check.
	3.	In Intune portal (https://endpoint.microsoft.com), open Devices → Compliance policies, find relevant policy and confirm assignments.
	4.	In Entra → Sign-ins, find the blocked sign-in and verify enforcement reasons include “Device not compliant”.

Evidence: Device compliance record screenshot, sign-in log showing device compliance failure.

Expected result: Only managed/compliant devices can access targeted resources.

⸻

TL1 — Defender for Cloud (Enabled, Default Policies)

Objective: Verify Defender for Cloud is active and default recommendations are on.

Resources: Global Admin/Sec Admin.

UI Steps:
	1.	Open https://portal.azure.com → search Defender for Cloud.
	2.	Select Environment settings → verify your subscription(s) show Defender plan enabled.
	3.	Capture the Secure Score and at least one recommendation or enabled policy.

Evidence: Screenshot of Defender status and secure score.

Expected result: Defender enabled for covered subscriptions with baseline telemetry.

⸻

TL2 — Safe Links & Safe Attachments (ATP)

Objective: Validate Safe Links & Safe Attachments protection for Teams, SharePoint, OneDrive, and Exchange.

Resources: testuser1@....

UI Steps:
	1.	In Defender portal https://security.microsoft.com → Email & collaboration → Policies & rules → Threat policies → open Safe Attachments and Safe Links configuration. Confirm policies are targeted to required users/locations.
	2.	Send a test phishing URL (from a phishing simulator authorized by your org) to testuser1@..., click link in Teams or Outlook Web — verify Safe Links behavior (warning or block).
	3.	Send an EICAR or simulator malicious file — verify Safe Attachments sandboxing and block/quarantine.

Evidence: ATP incident record, message trace, screenshot of block page.

Expected result: Malicious URLs and attachments are rewritten, blocked or quarantined.

⸻

TL3 — Customer Key Management (M365 CMK)

Objective: Verify Customer-Managed Keys (CMK) are configured where required.

Resources: Global Admin, Azure Key Vault.

UI Steps:
	1.	Go to Microsoft Purview (Compliance) https://compliance.microsoft.com → Information protection → Customer key (or search for Customer Key feature). Confirm key reference to Azure Key Vault.
	2.	In Azure Portal https://portal.azure.com → Key vaults, confirm CMK exists, key access policies are correct (Key Vault RBAC).

Evidence: Screenshot of CMK mapping and Key Vault policy entries.

Expected result: CMK configured & linked to tenant where required.

⸻

TL4 — M365 Auditing Enabled

Objective: Verify Unified Audit Logging and that audit events are captured.

Resources: Global Admin/Compliance Admin.

UI Steps:
	1.	Go to Microsoft Purview https://compliance.microsoft.com → Audit → Search.
	2.	Run a simple query: Operations = UserLoggedIn or AdminActivity, Date range = last 24 hours.
	3.	Confirm results include recent events, extract an entry.

Evidence: Screenshot of audit search results and exported CSV of events.

Expected result: Audit logs return entries for user/admin actions.

⸻

IP1 — Sensitivity Labels (Published & Visible)

Objective: Verify labels are published and selectable in Office apps.

Resources: Compliance Admin, testuser1@....

UI Steps:
	1.	Purview: https://compliance.microsoft.com → Information protection → Labels — verify list includes Highly Confidential, Confidential, Restricted, Public and that the label policy is published to user groups.
	2.	As testuser1@..., open Word/web Word → check the Sensitivity dropdown — labels should display.

Evidence: Screenshots of label list and Word UI.

Expected result: Labels appear and are usable.

⸻

IP2 — Default Label “Restricted” for Organisation Documents

Objective: Ensure new org documents default to Restricted label.

Steps:
	1.	As testuser1@..., create new Word document (web or desktop) and save to OneDrive/SharePoint.
	2.	Verify document sensitivity is set to Restricted automatically (metadata).

Evidence: Document properties screenshot (sensitivity label metadata), Purview label policy screenshot.

Expected result: Documents created within scope auto-labeled Restricted.

⸻

IP3 — Prevent Sensitivity Downgrade (No Reduction)

Objective: Ensure labels cannot be downgraded without approval/logging.

Steps:
	1.	Open a Highly Confidential document as testuser1@....
	2.	Try to change label to Public — system should block or require justification.
	3.	Capture Purview incident or audit entry for attempted downgrade.

Evidence: Screenshot of blocked action and audit entry.

Expected result: Downgrade prevented or logged with justification.

⸻

DLP1 — DLP Blocking for Personal Data & Payment Info

Objective: Validate DLP rules for Malaysia/SG phone/ID, passport numbers, credit cards and encrypted attachments.

Steps:
	1.	In Purview → Data loss prevention → find rule(s) for the specified patterns. Confirm targets (Exchange, SharePoint, OneDrive, Teams).
	2.	As testuser1@..., send an email containing synthetic test data matching the patterns (use test numbers) or upload document with such patterns to SharePoint.
	3.	Verify DLP action: block or quarantine and create an incident.

Evidence: DLP incident ID, policy name, screenshot of blocked UI and Purview incident.

Expected result: DLP triggers and blocks policy violations.

⸻

DLP2 — Block USB/Bluetooth on Endpoints

Objective: Ensure endpoint policy blocks USB storage and Bluetooth transfers.

Steps:
	1.	Confirm Intune device configuration policy disables USB mass storage and Bluetooth file exchange for corporate devices in https://endpoint.microsoft.com.
	2.	On corporate laptop, plug in USB drive and attempt to copy file — should be blocked.
	3.	Attempt Bluetooth transfer — blocked.

Evidence: Endpoint policy screenshot and OS block message screenshot; Intune device diagnostic log for blocked operations.

Expected result: Device policies enforce USB/Bluetooth block.

⸻

DLM1 — Retention Policy 15 Years

Objective: Validate retention policy applied for Exchange, SharePoint, Teams, Groups and Copilot (if applicable).

Steps:
	1.	Purview: https://compliance.microsoft.com → Information governance / Records management → Open retention policies → verify policy named/targeted with 15-year retention.
	2.	Create sample content in each service, delete it, then verify it remains recoverable / preserved per policy.

Evidence: Screenshot of retention policy definition and a saved record indicating it’s under retention hold.

Expected result: 15-year retention active and enforced.

⸻

5. R1 — Entra ID Built-in Role Assignment Validation (detailed, production grade)

Scope: only user assignment & least privilege checks (Global Admin, Security Admin, User Admin, Privileged Role Admin, Conditional Access Admin, Authentication Admin). Assume roles already created and used in tenant.

5.1 What to validate (summary)
	•	Who is assigned to each privileged directory role (member list).
	•	Assignment type: Permanent vs Eligible (PIM).
	•	Overlap (users assigned to multiple high privileged roles).
	•	Recent usage/last sign-in of privileged accounts (detect stale or orphaned privileged accounts).
	•	Whether MFA & CA policies protect directory roles (enforced for sign-in).
	•	Whether assignment approvals/justifications exist (for PIM-eligible roles).

5.2 UI-Based Validation (Entra Portal)

A. Export role assignments (UI)
	1.	Sign in as Global Admin: https://entra.microsoft.com.
	2.	Left nav → Roles & administrators.
	3.	Click the role to validate (e.g., Global Administrator).
	4.	View Members. Click Download or Export (if available) — export CSV to capture DisplayName, UserPrincipalName, AssignmentType, AssignedDate.
	•	If there is no export button on your tenant blade, use the top-right … or use PowerShell below.

Evidence: Screenshot of role page and exported CSV.

B. Review PIM (Privileged Role assignments & activation)
	1.	Azure Portal: https://portal.azure.com.
	2.	Search Privileged Identity Management → Azure AD roles.
	3.	Select Assignments. Filter by role or user. Columns show Member, Assignment state (Eligible/Active), Assignment start/end, Assignment Approver.
	4.	If PIM is configured, open Audit history → export role activation events.

Evidence: Screenshot of PIM Assignments, CSV of PIM assignment list, PIM activation logs.

C. Verify CA policy targets Directory roles
	1.	Entra → Security → Conditional Access → open policy that enforces MFA.
	2.	In Assignments → Users and groups → ensure Directory roles are included (e.g., Global Administrator).
	3.	Capture policy screenshot.

Evidence: Screenshot of CA policy showing Directory roles in scope.

5.3 Command Line / Scripted Validation

Use either AzureAD (commonly available) or Microsoft Graph PowerShell (recommended for long term). Examples below:

Option 1 — AzureAD Module (PowerShell)

Install-Module AzureAD (if not installed). Note: AzureAD module is widely used but being deprecated — Microsoft Graph PowerShell is recommended for new automation.

# 1. Connect
Connect-AzureAD

# 2. Get a directory role object, example Global Administrator
$role = Get-AzureADDirectoryRole | Where-Object {$_.DisplayName -eq "Global Administrator"}
# 3. List members
Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId | Select DisplayName, UserPrincipalName, ObjectId | Export-Csv -Path .\GlobalAdminMembers.csv -NoTypeInformation

Option 2 — Microsoft Graph PowerShell (recommended)

Install-Module Microsoft.Graph -Scope CurrentUser
Connect-MgGraph -Scopes "Directory.Read.All","RoleManagement.Read.Directory","AuditLog.Read.All"
# get role templates and roles
$roles = Get-MgDirectoryRole
$grole = $roles | Where-Object {$_.DisplayName -eq "Global Administrator"}
# To list members via REST (recommended) because Graph PowerShell cmdlets names vary in versions:
$members = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($grole.Id)/members"
$members.value | Select displayName,userPrincipalName | Export-Csv members.csv -NoTypeInformation

Option 3 — Microsoft Graph REST API (Graph Explorer / curl)
	1.	Get directory role id:

GET https://graph.microsoft.com/v1.0/directoryRoles?$filter=displayName eq 'Global Administrator'

	2.	Get members:

GET https://graph.microsoft.com/v1.0/directoryRoles/{directoryRole-id}/members

What to capture from scripts:
	•	Exported CSV listing role members and their UPNs, ObjectIds, assignment type (if PIM shows required fields).
	•	Timestamps and who performed the role assignment (from Entra audit logs).

5.4 Audit logs to collect & verify
	•	Entra Audit logs: https://entra.microsoft.com → Monitoring → Audit logs. Filter Activity = Role management or Add member to role and note Initiated by, Target, Date/Time. Export CSV.
	•	PIM audit: Azure Portal → Privileged Identity Management → Audit history. Look for role activations and assignment writes.
	•	Entra Sign-ins: https://entra.microsoft.com → Monitoring → Sign-ins: for each privileged user, collect recent sign-in events and confirm MFA enforcement (Conditional Access evaluation details).

Audit evidence fields to capture:
	•	UserPrincipalName, RoleName, AssignmentType (Eligible/Active/Permanent), AssignedBy, AssignedOn, LastSignInDate, MFAStatus, PIMActivationEvents (IDs), AuditLogEventId or RequestId.

5.5 Acceptance Criteria & Checks (Least-Privilege)
	1.	Maximum allowed Global Admins: pre-agreed threshold (e.g., ≤ 3). If exceeded → FAIL.
	2.	No user should be a member of more than one high-privilege role unless justified (e.g., a break-glass account). Flag any multi-role users.
	3.	No permanent assignments for high-privilege roles — prefer PIM eligible assignments. If permanent assignments exist, they must be justified and logged.
	4.	All privileged accounts must have MFA & CA enforcement — verify sign-in logs show MFA Required & Satisfied.
	5.	Stale privileged accounts: privileged accounts without sign-ins for >90 days should be flagged.
	6.	Role assignment approval & justification: PIM assignments should show approvers and justification.

5.6 Example Test Cases (Role Assignment)

Test Case R1-01 — Global Admin membership export
	•	Action: Export Global Admin members via Entra UI and via PowerShell.
	•	Expected: CSV contains only authorized users; count ≤ threshold.
	•	Evidence: GlobalAdminMembers.csv, Entra UI screenshot.

Test Case R1-02 — User Admin cannot perform Security Admin tasks
	•	Action: Sign in as useradmin@... → attempt to open Conditional Access policy editor.
	•	Expected: Operation denied.
	•	Evidence: UI screenshot of access denied; Entra audit event.

Test Case R1-03 — Privileged Role Admin assignments via PIM
	•	Action: As Privileged Role Admin (or test account), add an eligible assignment for a test user via PIM. Check PIM audit.
	•	Expected: Assignment created as Eligible; activation requires justification.
	•	Evidence: PIM assignment screenshot and audit log.

5.7 Remediation guidance (when checks fail)
	•	Remove unnecessary permanent role assignments; convert to PIM eligible.
	•	Replace global permanent assignments with PIM just-in-time activation.
	•	Require access reviews for privileged roles (Azure AD Access Reviews).
	•	Enforce CA policies targeting directory roles (MFA + compliant device + named locations).
	•	Decommission stale privileged accounts or rotate credentials.

⸻

6. R2 — Azure RBAC Built-in Role Assignment Validation (detailed)

Scope: Owner, Contributor, Reader, User Access Administrator, Key Vault roles — validate assignment and least privilege at subscription / RG / resource scope.

6.1 What to validate
	•	Who is assigned each RBAC role at subscription / resource-group scope.
	•	Whether any user has excessive cross-scope privileges (e.g., Contributor at subscription + Owner at RG).
	•	Whether resource owners and subscription owners are appropriate and minimized.
	•	Key Vault RBAC role separation (Secrets/Certs/Keys/Reader).

6.2 UI Steps (Azure Portal)

A. Subscription / RG role exports:
	1.	Log in to https://portal.azure.com as Global Admin.
	2.	Navigate to Subscriptions → select the subscription to test.
	3.	On the left blade → Access control (IAM) → Role assignments.
	4.	Use the filter (Role) to view Owners, Contributors, Readers, User Access Admins. Click Download (Export to CSV) to export role assignments for the subscription.
	5.	For a Resource Group: Subscriptions → Subscription → Resource groups → select RG → Access control (IAM) → Role assignments → Export CSV.

Evidence: CSV of role assignments for subscription/RG, UI screenshot.

B. Activity log checks for role assignment operations:
	1.	Azure Portal → Monitor → Activity log.
	2.	Filter by Operation name = Create role assignment (Microsoft.Authorization/roleAssignments/write) and time range for recent assignments.
	3.	Click an event → copy Correlation ID and screenshot details.

Evidence: Activity log entry, Correlation ID.

6.3 Azure CLI Steps (scripted)

Prerequisite: az login as user with appropriate access.
	•	List role assignments for specific user:

az role assignment list --assignee user@yourtenant.onmicrosoft.com --output json > assignments_user.json

	•	List role assignments for a subscription (filter by role)

az role assignment list --scope /subscriptions/<SUBSCRIPTION_ID> --role "Owner" --output json > owners_subscription.json

	•	Convert to table for quick view:

az role assignment list --assignee user@yourtenant.onmicrosoft.com --output table

Evidence: JSON/CSV exports showing assignments.

6.4 PowerShell (Az module) steps

Connect-AzAccount
# List assignments for user
Get-AzRoleAssignment -SignInName "testuser1@yourtenant.onmicrosoft.com" | Select-Object RoleDefinitionName, Scope, DisplayName | Export-Csv -Path .\roleassignments_user1.csv -NoTypeInformation

# List owners at subscription level
Get-AzRoleAssignment -RoleDefinitionName "Owner" -Scope "/subscriptions/<SUBSCRIPTION_ID>" | Export-Csv owners.csv -NoTypeInformation

Evidence: CSVs exported, showing role names and scopes.

6.5 Key Vault role validation (RBAC model)

UI Steps:
	1.	Go to https://portal.azure.com → Key vaults → open test Key Vault.
	2.	Access control (IAM) → Role assignments → filter by role (Key Vault Administrator, Key Vault Secrets Officer). Export the list.
	3.	For vault-level operations, check Access policies (if using policy-based auth) as well.

CLI: Use Azure CLI / Azure PowerShell to list role assignments at resource scope:

# example: list role assignments for the key vault resource id
az role assignment list --scope /subscriptions/<subid>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<vaultname> --output json > kv_roleassignments.json

Test operations (negative checks):
	•	As test-reader@... assigned Key Vault Reader — try to retrieve a secret value using Azure CLI or portal; should be denied.
	•	As test-secrets@... (Secrets Officer) — create a secret; verify write succeeds.

Evidence: Activity log entries like Microsoft.KeyVault/vaults/secrets/set and denied authorization responses.

6.6 Acceptance Criteria & Remediation
	•	Owner assignments limited to minimal administrators (e.g., infra owners) and recorded.
	•	Contributor cannot assign roles — verify denied attempts in Activity log.
	•	Readers cannot modify resources.
	•	Key Vault roles are segregated: secrets management separated from keys/certs and readers.

Remediation: Re-scope roles to least privilege; use RBAC scopes (RG or resource) rather than subscription-wide where possible; implement Privileged Access for subscription critical roles.

⸻

7. Evidence Collection Template (single source of truth)

Create a folder in SharePoint e.g.,
https://yourtenant.sharepoint.com/sites/SecurityValidation/Shared%20Documents/ValidationEvidence

File naming & content requirements:
	•	File name convention: YYYYMMDD_ControlID_Name_TestAccount_Result.(png|csv|json|txt)
	•	e.g., 20250926_CA1_MFA_Admin_globaladmin_pass.png, 20250926_R1_Export_globaladmins.csv

Evidence Items per test (minimum):
	1.	UI screenshot (policy, settings or error) — include visible timestamp.
	2.	Exported CSV / JSON of role assignments or sign-in logs.
	3.	Audit / Activity Log entry reference (Request ID / Correlation ID).
	4.	Short test notes (who executed the test, time, environment).

Example CSV headers (role assignments):

RoleName,UserPrincipalName,DisplayName,AssignmentType,PIMState,AssignedBy,AssignedOn,ObjectId,Scope
Global Administrator,alice@...,Alice Smith,Permanent,Active,admin@...,2025-01-15,xxxxx,/directoryRoles/...

Example evidence entry (structured):
	•	ControlID: R1
	•	Test executed: Export Global Admin membership via PowerShell and Entra UI
	•	Evidence files: 20250926_R1_export_globaladmins.csv, 20250926_R1_enra_ui_globaladmins.png
	•	Audit IDs: Entra Audit Log RequestId: 1234-5678
	•	Status: Pass / Fail
	•	Notes: If fail, include remediation plan & owner.

⸻

8. Acceptance Criteria (summary)
	•	No more than agreed # of Global Admins (policy-defined).
	•	All directory role members must have MFA and CA enforcement.
	•	No user is assigned excessive roles without business justification.
	•	PIM used for privileged roles where available; permanent assignments minimized.
	•	Azure RBAC assignments follow least privilege and role scope rules; no Contributor or Owner role abuse.
	•	DLP and IP rules block sample PII and prevent downgrade attempts.
	•	Device compliance prevented access from un-enrolled devices.

⸻

9. Remediation Guidance (when tests fail)
	1.	Remove role from users lacking business justification.
	2.	Convert permanent assignments to Eligible in PIM and require approval & MFA.
	3.	Add CA policies to include Directory roles as policy targets (MFA + compliant device + Named Locations).
	4.	Configure Access Reviews for directory roles (Azure AD Access reviews).
	5.	Enforce key DLP and IP policy updates and rerun tests.
	6.	Document remediation steps and re-run failed tests; maintain remediation log.

⸻

10. Conclusion & Next Steps

This playbook provides a complete, repeatable, auditable set of tests to validate your security baseline across Entra ID, M365, and Azure RBAC. Next steps:
	•	Run the playbook with the test accounts and devices described.
	•	Collect all evidence in the central SharePoint library and mark test case statuses (Pass/Fail).
	•	Implement remediation items and re-test failed controls.
	•	Schedule periodic (quarterly) revalidation and add selected tests to continuous monitoring (Secure Score, Defender recommendations, automated scripts).

⸻

If this final printed version looks correct, I’ll generate the Markdown file (exact same content formatted to .md) and a spreadsheet (Excel) with one test case per row (columns: TestCaseID, ControlID, Steps, Expected, Actual, Evidence links) — ready for use in your QA/Test management system.

Which output would you like next? Markdown file, Excel workbook, or both?hi


