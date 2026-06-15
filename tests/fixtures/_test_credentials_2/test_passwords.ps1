# ============================================================================
# TEST FILE — Injected for HemSpect Scanner Validation (PowerBI EXE Package)
# ============================================================================

# --- Test Case 1: Service account password ---
$svcPassword = "Service@ccount#2024!"

# --- Test Case 2: Database password in variable ---
$password = 'Pr0duction_DB_P@ss!'

# --- Test Case 3: Connection string ---
$connStr = "Data Source=SQL01;Initial Catalog=PowerBI;User ID=pbi_admin;Password=PBI#Admin2024"

# --- Test Case 4: PSCredential construction ---
$credential = New-Object System.Management.Automation.PSCredential("deploy_user", (ConvertTo-SecureString "D3ploy_S3cret!" -AsPlainText -Force))

# --- Test Case 5: Bearer token ---
$token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
