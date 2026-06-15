# ============================================================================
# TEST FILE — False Positive Validation (PowerBI EXE Package)
# ============================================================================

# --- FP: Encrypted DPAPI SecureString ---
$encPassword = ConvertTo-SecureString "01000000d08c9ddf0115d1118c7a00c04fc297eb" -Key @(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16)

# --- FP: Password prompt (not hardcoded) ---
$userPass = Read-Host -Prompt "Enter your password" -AsSecureString

# --- FP: Comment mentioning password ---
# The password must meet complexity requirements

# --- FP: Template placeholder ---
$pwd = '<CHANGE_ME>'
