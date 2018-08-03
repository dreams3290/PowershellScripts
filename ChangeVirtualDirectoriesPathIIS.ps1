$Servers = @("server1","server2")
foreach ($Server in $Servers )
{
[Void][Reflection.Assembly]::LoadWithPartialName("Microsoft.Web.Administration")
$siteName = "name of the iis site"
$newVDPath = "path to the new themes"
$vdname="name of the virtual directory"
$serverManager = [Microsoft.Web.Administration.ServerManager]::OpenRemote("$Server")
$site = $serverManager.Sites | where { $_.Name -eq $siteName }
$rootApp = $site.Applications | where { $_.Path -eq "/" }
$exisitingVdir = $rootApp.VirtualDirectories | where { $_.Path -eq "/$vdname" }
$exisitingVdir.PhysicalPath = $newVDPath
$serverManager.CommitChanges()
}