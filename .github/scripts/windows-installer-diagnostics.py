#!/usr/bin/env python3
"""Temporary native installer diagnosis on a fresh disposable Windows runner."""
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

if sys.platform != 'win32' or os.environ.get('OCVPN_DISPOSABLE_RUNNER') != '1':
    raise SystemExit('Disposable Windows runner required')

packages = sorted(Path('artifacts').glob('openconnect-cli-*-setup.exe' if sys.argv[1] == 'cli' else 'OpenConnect GUI*-setup.exe'))
if len(packages) != 1:
    raise SystemExit('Expected exactly one installer for the selected flavor')
command = [sys.executable, '-u', 'packaging/smoke.py', str(packages[0])]
print('Starting actual native installation smoke:', command, flush=True)
process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
try:
    output, _ = process.communicate(timeout=180)
    print(output.decode('utf-8', errors='backslashreplace'), flush=True)
    raise SystemExit(process.returncode)
except subprocess.TimeoutExpired:
    print('Native installation has not completed after 180 seconds; inspecting its own process tree and dialogs.', flush=True)

ps = subprocess.run([
    'pwsh.exe', '-NoProfile', '-NonInteractive', '-Command',
    '[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); '
    'Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine | ConvertTo-Json -Compress'
], check=True, stdout=subprocess.PIPE, timeout=30)
processes = json.loads(ps.stdout)
pids = {process.pid}
while True:
    children = {item['ProcessId'] for item in processes if item['ParentProcessId'] in pids}
    if children.issubset(pids):
        break
    pids.update(children)
for item in processes:
    if item['ProcessId'] in pids:
        print('Installer process:', json.dumps(item), flush=True)

user32 = ctypes.WinDLL('user32', use_last_error=True)
callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
user32.EnumWindows.argtypes = [callback_type, wintypes.LPARAM]
user32.EnumChildWindows.argtypes = [wintypes.HWND, callback_type, wintypes.LPARAM]
user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]

def describe_window(hwnd):
    text = ctypes.create_unicode_buffer(4096)
    kind = ctypes.create_unicode_buffer(256)
    user32.GetWindowTextW(hwnd, text, len(text))
    user32.GetClassNameW(hwnd, kind, len(kind))
    if text.value:
        print('Installer window:', json.dumps({'class': kind.value, 'text': text.value}), flush=True)

@callback_type
def child_window(hwnd, parameter):
    describe_window(hwnd)
    return True

@callback_type
def top_window(hwnd, parameter):
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    if pid.value in pids:
        describe_window(hwnd)
        user32.EnumChildWindows(hwnd, child_window, 0)
    return True

user32.EnumWindows(top_window, 0)
root = Path(os.environ['ProgramW6432']) / 'OpenConnect GUI'
for path in [root, root / 'ocvpn-installer.exe', Path(os.environ['ProgramData']) / 'OpenConnectGUI']:
    if path.exists():
        result = subprocess.run([
            'pwsh.exe', '-NoProfile', '-NonInteractive', '-Command',
            '$acl = Get-Acl -LiteralPath $env:OCVPN_DIAGNOSTIC_PATH; $acl | Format-List Path,Owner,Sddl'
        ], env={**os.environ, 'OCVPN_DIAGNOSTIC_PATH': str(path)},
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
        print(result.stdout.decode('utf-8', errors='backslashreplace'), flush=True)
for guard in Path(tempfile.gettempdir()).glob('*/ocvpn-package-guard.exe'):
    try:
        result = subprocess.run([str(guard), 'prepare'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
        print('Original embedded guard result:', result.returncode, result.stdout.decode('utf-8', errors='backslashreplace'), flush=True)
    except subprocess.TimeoutExpired:
        print('Original embedded guard also timed out.', flush=True)
helper = root / 'ocvpn-installer.exe'
if helper.is_file():
    try:
        result = subprocess.run([str(helper), 'status'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
        print('Installed helper status:', result.returncode, result.stdout.decode('utf-8', errors='backslashreplace'), flush=True)
    except subprocess.TimeoutExpired:
        print('Installed helper status also timed out.', flush=True)

# This is only the process tree launched above, on a disposable runner. Preserve
# the installed files and service; do not pretend that this is an uninstall.
if process.poll() is None:
    subprocess.run(['taskkill.exe', '/PID', str(process.pid), '/T', '/F'], check=False, timeout=30)
output, _ = process.communicate(timeout=30)
print(output.decode('utf-8', errors='backslashreplace'), flush=True)
raise SystemExit('Unattended native installation stalled; dialog/process evidence recorded above')
