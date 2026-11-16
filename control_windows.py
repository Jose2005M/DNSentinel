"""Componente elevado: configura/restaura DNS y supervisa la sesión local."""
import argparse
import ctypes
import hmac
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

from desktop.core import NetworkProtection, ProtectionError, atomic_json, read_json
from desktop.probe import healthy
from desktop.windows import Process, WindowsDNS, mutex, secure_state_directory


def status(session, phase, message):
    atomic_json(session/'status.json', {'phase':phase,'message':message,'time':time.time()})


def stop_server(session, request):
    atomic_json(session/'server-stop.json', {'token':request['token']})


def valid_request(session):
    request=read_json(session/'request.json')
    uuid.UUID(request['run_id']);uuid.UUID(request['adapter_guid'])
    if not re.fullmatch(r'[0-9a-f]{64}',request['token']):
        raise ProtectionError('Identificador de sesión inválido.')
    for field in ('controller_pid','server_pid'):
        if type(request[field]) is not int or request[field]<1:
            raise ProtectionError('Proceso de sesión no válido.')
    return request


def restore_owned(protection, session, request):
    state=protection.state()
    if state and state['run_id']==request['run_id']:
        protection.restore(request['run_id'])
        status(session,'restored','DNS original restaurado. Protección detenida.')
        stop_server(session,request)
        return True
    return False


def watchdog(session,request,helper_pid,protection):
    handles=[Process(pid=p) for p in (helper_pid,request['controller_pid'],request['server_pid'])]
    try:
        atomic_json(session/'watchdog-ready.json',{'run_id':request['run_id']})
        while all(handle.alive() for handle in handles):
            state=protection.state()
            if not state or state['run_id']!=request['run_id'] or state['phase']=='restored':
                return
            time.sleep(.5)
        # Un cierre inesperado no impide que este proceso separado restaure la red.
        for attempt in range(3):
            try:
                restore_owned(protection,session,request)
                return
            except Exception:
                if attempt<2:
                    time.sleep(1)
        status(session,'restore_failed','No se pudo restaurar automáticamente. Usa Restaurar DNS guardado; no borres el respaldo.')
    finally:
        for handle in handles:
            handle.close()


def protect(session,request,protection):
    handles=[];watcher=None;prepared=False
    with mutex('DNSentinel.Session',0):
        try:
            handles=[Process(pid=p) for p in (request['controller_pid'],request['server_pid'])]
            if not healthy(request['token'],ipv6=request['ipv6']):
                raise ProtectionError('El DNS propio no responde en UDP/TCP. No se cambió la red.')
            protection.prepare(request['adapter_guid'],request['run_id'])
            prepared=True
            watcher=subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'--session',str(session),
                                      '--watchdog','--helper-pid',str(os.getpid())],
                                     creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0),close_fds=True)
            for _ in range(100):
                if watcher.poll() is not None:
                    raise ProtectionError('No se pudo iniciar el supervisor de recuperación.')
                if (session/'watchdog-ready.json').exists():
                    if read_json(session/'watchdog-ready.json').get('run_id')==request['run_id']:
                        break
                time.sleep(.1)
            else:
                raise ProtectionError('El supervisor no confirmó el inicio; no se activó el filtro.')
            if not all(handle.alive() for handle in handles) or not healthy(request['token'],ipv6=request['ipv6']):
                raise ProtectionError('La aplicación se cerró antes de activar la protección.')
            protection.activate(request['run_id'])
            status(session,'active','Protección activa. El adaptador utiliza DNSentinel. Mantén esta ventana abierta.')
            failures=0
            while all(handle.alive() for handle in handles) and watcher.poll() is None:
                stop=session/'stop.json'
                if stop.exists() and hmac.compare_digest(read_json(stop).get('token',''),request['token']):
                    break
                failures=0 if healthy(request['token'],ipv6=request['ipv6']) else failures+1
                if failures>=2:
                    break
                time.sleep(1)
            status(session,'restoring','Restaurando el DNS anterior…')
        finally:
            try:
                if prepared:
                    restore_owned(protection,session,request)
            except Exception as error:
                status(session,'restore_failed',str(error)+' Usa Restaurar DNS guardado para reintentar.')
            for handle in handles:
                handle.close()
            if watcher is not None:
                # No matar al supervisor si hay un respaldo pendiente de restauración.
                state=protection.state()
                if state and state['phase']=='restored':
                    try:
                        watcher.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        status(session,'restored','DNS restaurado; el supervisor cerrará su comprobación.')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--session',required=True)
    parser.add_argument('--restore-only',action='store_true')
    parser.add_argument('--watchdog',action='store_true')
    parser.add_argument('--helper-pid',type=int)
    args=parser.parse_args()
    session=Path(args.session).resolve()
    expected=Path(__file__).resolve().parent/'instance'/'launcher'
    try:
        if session.parent != expected.resolve():
            raise ProtectionError('La sesión debe estar dentro de instance/launcher del proyecto.')
        uuid.UUID(session.name)
        if os.name!='nt' or not ctypes.windll.shell32.IsUserAnAdmin():
            raise ProtectionError('Se requieren los permisos de administrador solicitados por Windows.')
        protection=NetworkProtection(WindowsDNS(),secure_state_directory(),mutex)
        if args.restore_only:
            with mutex('DNSentinel.Session',0):
                state=protection.restore()
                message='DNS original restaurado.' if state else 'No hay configuración guardada pendiente.'
                status(session,'restored',message)
            return
        request=valid_request(session)
        if args.watchdog:
            watchdog(session,request,args.helper_pid,protection)
        else:
            protect(session,request,protection)
    except Exception as error:
        try:
            # No ocultar un fallo de restauración con un error secundario.
            old=read_json(session/'status.json') if (session/'status.json').exists() else {}
            if old.get('phase') not in ('restored','restore_failed'):
                status(session,'error',str(error))
        except (OSError,ValueError):
            sys.exit(1)
        sys.exit(1)


if __name__=='__main__':
    main()
