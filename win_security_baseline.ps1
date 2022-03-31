# 20220327 v0.1 LeN
# 

# 
# $Share = \\Directory

# Create new directory
if (Test-Path -Path C:\temp) {
    "OK"
} else {   
New-Item C:\temp -ItemType "directory"
}

#
$HostName = Get-WMIObject Win32_ComputerSystem | Select Name

$FileDate = ((Get-Date).ToString("yyyyMMdd"))
$FileName = $FileDate + $HostName

$FilePath = New-Item C:\temp\"$FileName".log



# List Hostname
Get-CimInstance -ClassName Win32_ComputerSystem | Out-File -Append -FilePath $FilePath

# List IP Addresses
Get-CimInstance -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=$true | Select-Object -ExpandProperty IPAddress | Out-File -Append -FilePath $FilePath

# List installed hotfixes
Get-CimInstance -ClassName Win32_QuickFixEngineering | Out-File -Append -FilePath $FilePath

# List operating system version information
Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -Property BuildNumber,BuildType,OSType,ServicePackMajorVersion,ServicePackMinorVersion | Out-File -Append -FilePath $FilePath

# List local users and owners
Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -Property NumberOfLicensedUsers,NumberOfUsers,RegisteredUser | Out-File -Append -FilePath $FilePath

# List Services
Get-CimInstance -ClassName Win32_Service | Select-Object -Property Status,Name,DisplayName | Out-File -Append -FilePath $FilePath

# 
Get-WmiObject -Class Win32_Product | Out-File -Append -FilePath $FilePath

#
# $DestPath = C:\dest\
# Get-ChildItem $FilePath | Move-Item -Destination $DestPath



