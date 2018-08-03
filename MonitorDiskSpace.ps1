$smtpServer = ""
$senderEmail=""
$receiverEmail=""
$list = "path to server list" 
function sendemail{
   param (
       [string] $smtpfrom=$null,
       [string] $smtpTo=$null,
       [string] $EmailSubject=$null,
       [string] $mailBody = $null,
       [boolean] $IsBodyHTMLOK = $false
   ) 
   $message = New-Object System.Net.Mail.MailMessage $smtpfrom, $smtpto
   $message.Subject = $EmailSubject
   $message.IsBodyHTML = $IsBodyHTMLOK
   $message.Body = $mailBody
   $smtp = New-Object Net.Mail.SmtpClient($smtpServer)
   $smtp.Send($message)
}
2
$HostList = get-content $list 
[decimal]$thresholdspace = 20
$tableFragment= Get-WMIObject  -ComputerName $HostList Win32_LogicalDisk `
| select __SERVER, DriveType, VolumeName, Name, @{n='Size (Gb)' ;e={"{0:n2}" -f ($_.size/1gb)}},@{n='FreeSpace (Gb)';e={"{0:n2}" -f ($_.freespace/1gb)}}, @{n='PercentFree';e={"{0:n2}" -f ($_.freespace/$_.size*100)}} `
| Where-Object {$_.DriveType -eq 3 -and [decimal]$_.PercentFree -lt [decimal]$thresholdspace} `
| ConvertTo-HTML -fragment
$HTMLmessage = @"
<font color=""black"" face=""Arial, Verdana"" size=""3"">
<u><b>Disk Space Storage Alert</b></u>
<br>This report was generated because the drive(s) listed below have less than $thresholdspace % free space. Drives above this threshold will not be listed.
<br>
<style type=""text/css"">body{font: .8em ""Lucida Grande"", Tahoma, Arial, Helvetica, sans-serif;}
ol{margin:0;padding: 0 1.5em;}
table{color:#FFF;background:#0e174a;border-collapse:collapse;width:647px;border:5px solid #900;}
thead{}
thead th{padding:1em 1em .5em;border-bottom:1px dotted #FFF;font-size:120%;text-align:left;}
thead tr{}
td{padding:.5em 1em;}
tfoot{}
tfoot td{padding-bottom:1.5em;}
tfoot tr{}
#middle{background-color:#900;}
</style>
<body BGCOLOR=""white"">
$tableFragment
</body>
"@
$regexsubject = $HTMLmessage
$regex = [regex] '(?im)<td>'
if ($regex.IsMatch($regexsubject)) {
                       sendemail -smtpfrom $senderEmail -smtpTo receiverEmail  -EmailSubject "Disk Space" -IsBodyHTMLOK $true -mailBody $HTMLmessage                     
}

