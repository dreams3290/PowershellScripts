#Script to restart IIS remotely
$servers="server1","server2"
   foreach ($server in $servers)
{
    Write-Host "Restarting IIS on server $server..."
    IISRESET $server /noforce
    Write-Host "IIS status for server $server"
    IISRESET $server /status
}
Write-Host IIS has been restarted on all servers

