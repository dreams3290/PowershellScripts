$server01 = "server-01"

$server02 = "server-02"

$server01Patches = get-hotfix -computer $server01 | Where-Object {$_.HotFixID -ne “File 1”}

$server02Patches = get-hotfix -computer $server02 | Where-Object {$_.HotFixID -ne “File 1”}

Compare-Object ($server01Patches) ($server02Patches) -Property HotFixID