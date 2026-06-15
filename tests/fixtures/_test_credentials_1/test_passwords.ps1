# ============================================================================
# TEST FILE — Injected for HemSpect Scanner Validation
# This file contains INTENTIONAL hardcoded passwords for testing detection.
# ============================================================================

# --- Test Case 1: Simple hardcoded password variable ---
$password = 'MySuperSecretPassword123!'

# --- Test Case 2: Database connection password ---
$dbPassword = "SqlServer@dmin2024"

# --- Test Case 3: PSCredential with plaintext SecureString ---
$cred = New-Object System.Management.Automation.PSCredential("admin", (ConvertTo-SecureString "P@ssw0rd!2024" -AsPlainText -Force))

# --- Test Case 4: API key embedded ---
$apiKey = "sk-proj-abc123def456ghi789jkl012mno345pqr"

# --- Test Case 5: Connection string with embedded password ---
$connectionString = "Server=myServer;Database=myDB;User Id=sa;Password=Str0ngP@ss!2024"

# --- Test Case 6: SMTP password ---
$smtpPassword = "EmailP@ss789!"
$smtp_pass = 'SmtpSecret#456'

# --- Test Case 7: AWS Access Key (fake) ---
$awsKey = "AKIAIOSFODNN7EXAMPLE"

# --- Test Case 8: Azure Storage Connection String ---
$azureConn = "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=abc123def456ghi789jkl012mno345pqr=="

# --- Test Case 9: GitHub Personal Access Token (fake) ---
$ghToken = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg"

# --- Test Case 10: Base64 encoded password ---
$secret = "password = 'TXlTdXBlclNlY3JldFBhc3N3b3JkMTIzIQ=='"

# --- Test Case 11: Password in registry write ---
Set-ItemProperty -Path "HKLM:\SOFTWARE\MyApp" -Name "ServicePassword" -Value "Registr7P@ssword!"

# --- Test Case 12: Multiple credentials in one line ---
$creds = @{ Username = "svc_account"; Password = "MultiLine#Secret99"; Domain = "CORP" }
