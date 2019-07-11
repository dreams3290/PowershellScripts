$dates=get-content "local data path"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
foreach ($date in $dates)
{
Invoke-RestMethod -Uri "enter URI here" -Method Post >>"path to the log file"
}