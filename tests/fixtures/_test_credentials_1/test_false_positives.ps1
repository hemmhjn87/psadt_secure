# ============================================================================
# TEST FILE — False Positive Validation
# These patterns should NOT be flagged as hardcoded passwords.
# ============================================================================

# --- FP Case 1: Encrypted SecureString with -Key (properly secured) ---
$securePassword = ConvertTo-SecureString "01000000d08c9ddf0115d1118c7a00c04fc297eb0100000036b4d5e7d43f874e" -Key (1..16)

# --- FP Case 2: Password policy documentation ---
# Password policy requires 8 chars minimum
# Set password expiry to 90 days

# --- FP Case 3: ADT Session configuration (standard PSADT) ---
$passwordPolicy = Get-ADDefaultDomainPasswordPolicy

# --- FP Case 4: Template placeholder ---
$password = '<YOUR_PASSWORD_HERE>'
$password = 'PLACEHOLDER'

# --- FP Case 5: Variable reference (not literal) ---
$password = $env:SERVICE_PASSWORD

# --- FP Case 6: Empty password check ---
if ($password -eq '') { Write-Host "Password is empty" }

# --- FP Case 7: Read-Host (interactive, not hardcoded) ---
$password = Read-Host -AsSecureString "Enter password"

# --- FP Case 8: Comment-only password mention ---
# password = 'this is just a comment and should not trigger'
