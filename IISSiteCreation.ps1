#import the required modules
Import-Module WebAdministration

#pass the parameters
$iisAppPoolName= "Name of the App pool"
$iisAppPoolDotNetVersion= "Dotnet Version"
$iisAppName= "Site Name"
$hostname= "HostName"
$VD1Name="Name of the Virtual directory 1"
$VD2Name="Name of the Virtual directory 2"
$VD1Path="Path to virtual directory 1"
$VD2Path="Path to virtual directory 2"
$appPoolsPath="IIS:\AppPools\"
#pass the credentials for app pool
$username="enter the app pool identity username"
$password="enter the app pool identity password"



#path to site directory and create if it doesnt exist.
$directoryPath = "folder where site code resides, create only if it doesnt exist"
If(!(test-path $directoryPath))
{
      New-Item -ItemType Directory -Force -Path $directoryPath
      
}

#navigate to the app pools root

Set-Location $appPoolsPath

#check if the app pool exists
if (!(Test-Path $iisAppPoolName -pathType container))
{
    #create the app pool
    $appPool = New-Item $iisAppPoolName
    $appPool | Set-ItemProperty -Name "managedRuntimeVersion" -Value $iisAppPoolDotNetVersion
    Set-ItemProperty $appPoolsPath\$iisAppPoolName -name processModel -value @{userName=$username;password=$password;identitytype=3}

}

#navigate to the sites root
Set-Location IIS:\Sites\

#check if the site exists
if (Test-Path $iisAppName -pathType container)
{
   return
}

#create the site
$iisApp = New-Item $iisAppName -bindings @{protocol="http";bindingInformation="*:80:$hostname"} -physicalPath $directoryPath
$iisApp | Set-ItemProperty -Name "applicationPool" -Value $iisAppPoolName

#Create the virtual directories

New-WebVirtualDirectory -Site $iisAppName -Name $VD1Name -PhysicalPath $VD1Path

New-WebVirtualDirectory -Site $iisAppName -Name $VD2Name -PhysicalPath $VD2Path




