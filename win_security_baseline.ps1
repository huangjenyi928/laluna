# 20220327 v0.1
# LeN

# Create new directory
$UseDate = "{0:yyyy-MM-dd}" -f (Get-Date)

$FilepPth = New-Item -name $UseDate -ItemType directory

# Get-ChildItem *.log | Move-Item -Destination $filepath



