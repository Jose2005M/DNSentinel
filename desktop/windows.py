"""Operaciones Windows: UAC, procesos, mutex y DNS por adaptador."""
import base64
from contextlib import contextmanager
import ctypes
from ctypes import wintypes
import json
import logging
import os
from pathlib import Path
import re
import subprocess
import uuid

from .core import ProtectionError, family_config


def system_exe(name):
    if os.name != 'nt':
        raise ProtectionError('El lanzador automático requiere Windows 10/11.')
    return str(Path(os.environ['SystemRoot'])/'System32'/name)


def command(args, timeout=25):
    result = subprocess.run(args, capture_output=True, timeout=timeout, creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0), check=False)
    if result.returncode:
        raise ProtectionError('Windows rechazó una operación de red. Revisa permisos, políticas y estado del adaptador.')
    return result.stdout


def prepare_session_access(path):
    """La cuenta de la GUI debe heredar lectura de archivos creados al elevar."""
    if os.name!='nt':
        return
    raw=command([system_exe('whoami.exe'),'/user','/fo','csv','/nh'])
    match=re.search(rb'S-1-[0-9]+(?:-[0-9]+)+',raw)
    if not match:
        raise ProtectionError('No se pudo identificar la cuenta de la ventana. El DNS no se modificó.')
    sid=match.group().decode('ascii')
    # Añadir solo lectura heredable para ESTA cuenta; no sustituir sus derechos.
    command([system_exe('icacls.exe'),str(path),'/grant','*'+sid+':(OI)(CI)R'])


def adapters():
    # Script fijo, sin interpolación de nombres, rutas o texto introducido por el usuario.
    script = """$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new()
$result=@(Get-NetAdapter -IncludeHidden | ForEach-Object {
 $a=$_
 $v6=Get-NetAdapterBinding -Name $a.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
 $v4=Get-NetAdapterBinding -Name $a.Name -ComponentID ms_tcpip -ErrorAction SilentlyContinue
 [pscustomobject]@{guid=$a.InterfaceGuid.ToString();index=[int]$a.ifIndex;name=$a.Name;up=($a.Status -eq 'Up');ipv4=[bool]$v4.Enabled;ipv6=[bool]$v6.Enabled}
})
ConvertTo-Json -InputObject $result -Compress
"""
    encoded = base64.b64encode(script.encode('utf-16le')).decode()
    raw = command([system_exe('WindowsPowerShell/v1.0/powershell.exe'),'-NoProfile','-NonInteractive','-EncodedCommand',encoded])
    result = json.loads(raw.decode('utf-8-sig'))
    for adapter in result:
        adapter['guid'] = str(uuid.UUID(adapter['guid'].strip('{}')))
    return result


class WindowsDNS:
    def adapter(self, guid):
        match = next((a for a in adapters() if a['guid']==guid),None)
        if match is None:
            raise ProtectionError('No se encuentra el adaptador del respaldo. Vuelve a conectarlo y reintenta.')
        return match

    def snapshot(self, adapter, family):
        import winreg
        service = 'Tcpip' if family==4 else 'Tcpip6'
        key = 'SYSTEM\\CurrentControlSet\\Services\\'+service+'\\Parameters\\Interfaces\\{'+adapter['guid']+'}'
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,key) as handle:
                try:
                    value = winreg.QueryValueEx(handle,'NameServer')[0]
                except FileNotFoundError:
                    value = ''
        except FileNotFoundError:
            value = ''
        values = value if isinstance(value,list) else re.split(r'[,;\s]+',value.strip())
        values = [v for v in values if v]
        return family_config('static' if values else 'automatic',values,family)

    def apply(self, adapter, family, config):
        config = family_config(config['source'], config['addresses'],family)
        base = [system_exe('netsh.exe'),'interface','ipv'+str(family)]
        target = 'name='+str(int(adapter['index']))
        if config['source']=='automatic':
            command([*base,'set','dnsservers',target,'source=dhcp'])
        else:
            command([*base,'set','dnsservers',target,'source=static','address='+config['addresses'][0],'validate=no'])
            for index,address in enumerate(config['addresses'][1:],2):
                command([*base,'add','dnsservers',target,'address='+address,'index='+str(index),'validate=no'])

    def secure_backup(self, path):
        command([system_exe('icacls.exe'),str(path),'/setowner','*S-1-5-32-544'])
        command([system_exe('icacls.exe'),str(path),'/reset'])

    def flush(self):
        # El fallo de una limpieza de caché no invalida una restauración ya confirmada.
        try:
            subprocess.run([system_exe('ipconfig.exe'),'/flushdns'], capture_output=True, timeout=15,
                           creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0), check=False)
        except (OSError, subprocess.TimeoutExpired):
            logging.getLogger('dnsentinel.launcher').warning('DNS configurado; limpieza de caché pendiente.')


def kernel():
    api=ctypes.WinDLL('kernel32',use_last_error=True)
    api.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD];api.OpenProcess.restype=wintypes.HANDLE
    api.CloseHandle.argtypes=[wintypes.HANDLE];api.CloseHandle.restype=wintypes.BOOL
    api.WaitForSingleObject.argtypes=[wintypes.HANDLE,wintypes.DWORD];api.WaitForSingleObject.restype=wintypes.DWORD
    api.CreateMutexW.argtypes=[ctypes.c_void_p,wintypes.BOOL,wintypes.LPCWSTR];api.CreateMutexW.restype=wintypes.HANDLE
    api.ReleaseMutex.argtypes=[wintypes.HANDLE];api.ReleaseMutex.restype=wintypes.BOOL
    return api


class Process:
    def __init__(self,pid=None,handle=None):
        self.api=kernel()
        self.handle=handle or self.api.OpenProcess(0x00100000,False,int(pid))
        if not self.handle:
            raise ProtectionError('El proceso que inició la protección ya terminó o no es accesible.')

    def alive(self):
        return self.api.WaitForSingleObject(self.handle,0)==258

    def close(self):
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle=None


@contextmanager
def mutex(name='DNSentinel.Restore',timeout=10000):
    api=kernel()
    handle=api.CreateMutexW(None,False,'Global\\'+name)
    if not handle:
        raise ProtectionError('No se pudo bloquear el control de DNS.')
    acquired=False
    try:
        acquired=api.WaitForSingleObject(handle,timeout) in (0,128)
        if not acquired:
            raise ProtectionError('Ya hay otra sesión de protección. Detén esa sesión antes de iniciar otra.')
        yield
    finally:
        if acquired:
            api.ReleaseMutex(handle)
        api.CloseHandle(handle)


def elevate(executable,arguments,cwd):
    class ExecuteInfo(ctypes.Structure):
        _fields_=[('cbSize',wintypes.DWORD),('fMask',wintypes.ULONG),('hwnd',wintypes.HWND),
                  ('lpVerb',wintypes.LPCWSTR),('lpFile',wintypes.LPCWSTR),('lpParameters',wintypes.LPCWSTR),
                  ('lpDirectory',wintypes.LPCWSTR),('nShow',ctypes.c_int),('hInstApp',wintypes.HINSTANCE),
                  ('lpIDList',ctypes.c_void_p),('lpClass',wintypes.LPCWSTR),('hkeyClass',wintypes.HKEY),
                  ('dwHotKey',wintypes.DWORD),('hIcon',wintypes.HANDLE),('hProcess',wintypes.HANDLE)]
    ole=ctypes.OleDLL('ole32');ole.CoInitializeEx(None,6)
    try:
        info=ExecuteInfo();info.cbSize=ctypes.sizeof(info);info.fMask=0x40|0x100
        info.lpVerb='runas';info.lpFile=str(executable);info.lpParameters=subprocess.list2cmdline(arguments)
        info.lpDirectory=str(cwd);info.nShow=0
        shell=ctypes.WinDLL('shell32',use_last_error=True)
        shell.ShellExecuteExW.argtypes=[ctypes.POINTER(ExecuteInfo)];shell.ShellExecuteExW.restype=wintypes.BOOL
        if not shell.ShellExecuteExW(ctypes.byref(info)):
            error=ctypes.get_last_error()
            if error==1223:
                raise ProtectionError('Se canceló la solicitud de administrador. El DNS no se cambió.')
            raise ProtectionError('No se pudo iniciar el componente de red con permisos de administrador.')
        return Process(handle=info.hProcess)
    finally:
        ole.CoUninitialize()


def machine_state():
    if os.name!='nt':
        raise ProtectionError('Solo disponible en Windows.')
    return Path(os.environ['ProgramData'])/'DNSentinel'/'NetworkProtection'/'state.json'


def secure_state_directory():
    """Respaldo persistente: escritura solo Administradores/SYSTEM; usuarios leen."""
    path=machine_state().parent
    for directory in [path.parent,path]:
        if directory.is_symlink() or (directory.exists() and directory.is_junction()):
            raise ProtectionError('La carpeta de respaldo no puede ser un enlace de sistema.')
        directory.mkdir(exist_ok=True)
        command([system_exe('icacls.exe'),str(directory),'/setowner','*S-1-5-32-544'])
        command([system_exe('icacls.exe'),str(directory),'/reset'])
        command([system_exe('icacls.exe'),str(directory),'/inheritance:r','/grant:r',
                 '*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F','*S-1-5-32-545:(OI)(CI)R'])
    if (path/'state.json').is_symlink():
        raise ProtectionError('El archivo de respaldo no puede ser un enlace.')
    return path/'state.json'
