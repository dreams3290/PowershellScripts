$list = "path to server list" 
$HostList = get-content $list
$lastpatch = Get-WmiObject -ComputerName $HostList Win32_Quickfixengineering | select @{Name="InstalledOn";Expression={$_.InstalledOn -as [datetime]}} | Sort-Object -Property Installedon | select-object -property installedon -last 1
Get-Date $lastpatch.InstalledOn -format yyyy-MM-dd
$lastpatch.date=Get-Date $lastpatch.InstalledOn -format yyyy-MM-dd
$lastpatch.serverName=$server