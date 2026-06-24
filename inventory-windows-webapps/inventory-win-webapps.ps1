Import-Module WebAdministration
Get-WebAppPoolState -Name "YourApplicationPoolName"

Get-WebAppPoolState

Import-Module WebAdministration
Get-Website | Select-Object Name, State, @{Name="ApplicationPool";Expression={(Get-ItemProperty IIS:\Sites\$($_.Name) | Select-Object applicationPool).applicationPool}}

Import-Module WebAdministration
Get-WebAppPool -Name "YourApplicationPoolName" | Select-Object Name, ManagedRuntimeVersion

$websitePath = (Get-Website -Name "YourWebsiteName").PhysicalPath
# Then you can examine files in $websitePath for clues (e.g., web.config, .aspx, .php files)

Get-AzWebApp -ResourceGroupName "YourResourceGroup" -Name "YourWebAppName" | Select-Object Name, State, Kind, @{Name="RuntimeStack";Expression={$_.SiteConfig.LinuxFxVersion}}

Get-Process -Name "ProcessName"