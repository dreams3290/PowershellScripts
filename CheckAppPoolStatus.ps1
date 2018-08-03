$ComputerName="computer name"
write-host "This is the script to check app pool status" -foreground "Red"
write-host "`n"
invoke-command -ComputerName $ComputerName -ScriptBlock {try{
Import-Module WebAdministration
$webapps = Get-WebApplication
$list = @()
foreach ($webapp in get-childitem IIS:AppPools)
{
$name = “IIS:AppPools\” + $webapp.name
$item = @{}
$item.WebAppName = $webapp.name
$item.Version = (Get-ItemProperty $name managedRuntimeVersion).Value
$item.State = (Get-WebAppPoolState -Name $webapp.name).Value

$obj = New-Object PSObject -Property $item
$list += $obj
}
Write-Host "This is '$computerName' status" -foreground "Blue"
$list | Format-Table -a -Property “WebAppName”, “State”
}catch
{
$ExceptionMessage = “Error in Line: ” + $_.Exception.Line + “. ” + $_.Exception.GetType().FullName + “: ” + $_.Exception.Message + ” Stacktrace: ” + $_.Exception.StackTrace
$ExceptionMessage
}    }
