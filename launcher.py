"""Ventana de protección Windows. El servidor web se ejecuta sin elevar permisos."""
import argparse
import http.client
import hashlib
import hmac
import ipaddress
import os
from pathlib import Path
import queue
import secrets
import ssl
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk
import uuid
import webbrowser

from desktop.core import ProtectionError, atomic_json, read_json
from desktop.chrome import ChromeController
from desktop.probe import healthy
from desktop.windows import adapters, elevate, machine_state, prepare_session_access

ROOT=Path(__file__).resolve().parent


def wait_server_ready(server,session,timeout=60,clock=None,pause=None):
    """Esperar con reloj monotónico; tolerar una escritura aún no visible."""
    clock=clock or time.monotonic
    pause=pause or time.sleep
    expected=read_json(Path(session)/'request.json')
    deadline=clock()+timeout
    log=Path(session)/'server.log'
    while clock()<deadline:
        try:
            ready=read_json(Path(session)/'server-ready.json')
            pid,port=ready.get('pid'),ready.get('port')
            if type(pid) is int and pid>0 and port==expected['web_port']:
                proof=hmac.new(expected['token'].encode(),f'{pid}:{port}'.encode(),hashlib.sha256).hexdigest()
                if isinstance(ready.get('proof'),str) and hmac.compare_digest(ready['proof'],proof):
                    return pid
        except (OSError,ValueError):
            # El archivo todavía no está disponible o su escritura no es visible.
            ready=None
        if server.poll() is not None:
            raise ProtectionError(f'El servidor terminó antes de iniciar. Comprueba los puertos y consulta el registro: {log}')
        pause(.2)
    raise ProtectionError(f'El servidor no confirmó la sesión en {timeout} segundos; no se modificó el DNS. Actualiza launcher.py y run.py juntos. Registro: {log}')


def verified_panel(port):
    connection=http.client.HTTPSConnection('localhost',port,context=ssl.create_default_context(),timeout=3)
    try:
        connection.request('GET','/login')
        response=connection.getresponse();response.read()
        return response.status==200
    finally:
        connection.close()


class Launcher:
    def __init__(self,root,recover=False):
        self.root=root;self.session=None;self.server=None;self.helper=None
        self.busy=False;self.active=False;self.closing=False;self.opened=False;self.events=queue.Queue()
        self.adapter_list=[];self.phase='idle';self.web_port=8444
        self.chrome=None;self.finishing=None;self.finished=None;self.chrome_pending=None
        root.title('DNSentinel · Protección local');root.geometry('660x540');root.minsize(620,520)
        root.configure(bg='#f3f7f6')
        style=ttk.Style();style.theme_use('clam')
        style.configure('TFrame',background='#f3f7f6');style.configure('TLabel',background='#f3f7f6',foreground='#193c38',font=('Segoe UI',10))
        style.configure('TButton',padding=10,font=('Segoe UI',10));style.configure('Primary.TButton',background='#087f69',foreground='white')
        frame=ttk.Frame(root,padding=28);frame.pack(fill='both',expand=True)
        ttk.Label(frame,text='DNSentinel',font=('Segoe UI',24,'bold')).pack(anchor='w')
        ttk.Label(frame,text='Protección DNS y Chrome · versión 1.2').pack(anchor='w',pady=(0,20))
        ttk.Label(frame,text='Adaptador que utiliza tu conexión a Internet').pack(anchor='w')
        row=ttk.Frame(frame);row.pack(fill='x',pady=(6,14))
        self.adapter=ttk.Combobox(row,state='readonly');self.adapter.pack(side='left',fill='x',expand=True)
        self.refresh_button=ttk.Button(row,text='Actualizar',command=self.refresh_adapters);self.refresh_button.pack(side='right',padx=(8,0))
        options=ttk.Frame(frame);options.pack(fill='x')
        ttk.Label(options,text='DNS externo (upstream)').grid(row=0,column=0,sticky='w')
        ttk.Label(options,text='Puerto del panel HTTPS').grid(row=0,column=1,sticky='w',padx=(20,0))
        self.upstream=ttk.Entry(options);self.upstream.insert(0,'1.1.1.1');self.upstream.grid(row=1,column=0,sticky='ew',pady=6)
        self.port=ttk.Entry(options,width=12);self.port.insert(0,'8444');self.port.grid(row=1,column=1,sticky='w',padx=(20,0),pady=6)
        options.columnconfigure(0,weight=1)
        self.message=tk.StringVar(value='Selecciona tu adaptador. El DNS solo cambia después de comprobar el servidor.')
        ttk.Label(frame,textvariable=self.message,wraplength=590,font=('Segoe UI',10,'bold')).pack(fill='x',pady=18)
        buttons=ttk.Frame(frame);buttons.pack(fill='x')
        self.start_button=ttk.Button(buttons,text='Iniciar protección',style='Primary.TButton',command=self.start);self.start_button.pack(side='left')
        self.stop_button=ttk.Button(buttons,text='Detener protección',command=self.stop,state='disabled');self.stop_button.pack(side='left',padx=10)
        self.panel_button=ttk.Button(buttons,text='Abrir panel',command=self.open_panel,state='disabled');self.panel_button.pack(side='left')
        self.restore_button=ttk.Button(frame,text='Restaurar DNS guardado',command=self.recover);self.restore_button.pack(anchor='w',pady=(14,10))
        ttk.Label(frame,text='Chrome requiere la extensión instalada una sola vez: consulta CHROME.md. Los botones sincronizan reglas y pestañas sin reiniciar el navegador.',wraplength=590,foreground='#405f58').pack(anchor='w')
        self.root.protocol('WM_DELETE_WINDOW',self.close)
        self.root.after(200,self.poll)
        if os.name!='nt':
            self.message.set('El modo automático requiere Windows 10/11. No se ha cambiado la red.')
            self.start_button.configure(state='disabled');self.restore_button.configure(state='disabled');self.refresh_button.configure(state='disabled')
        else:
            self.refresh_adapters()
            if recover:
                self.root.after(500,self.recover)

    def background(self,job):
        def execute():
            try:
                self.events.put(('result',job()))
            except Exception as error:
                self.events.put(('error',str(error)))
        threading.Thread(target=execute,daemon=True).start()

    def refresh_adapters(self):
        if self.busy or self.active:return
        self.message.set('Buscando adaptadores conectados…')
        self.background(lambda:('adapters',[a for a in adapters() if a['up'] and a['ipv4']]))

    def new_session(self):
        path=ROOT/'instance'/'launcher'/str(uuid.uuid4())
        path.mkdir(parents=True,mode=0o700)
        prepare_session_access(path)
        self.session=path;self.opened=False;self.finishing=None;self.finished=None;self.chrome_pending=None
        return path

    def chrome_controller(self):
        if not getattr(self,'chrome',None):
            self.chrome=ChromeController(ROOT/'instance/chrome')
        return self.chrome

    def set_busy(self,value):
        self.busy=value
        self.start_button.configure(state='disabled' if value or self.active else 'normal')
        self.restore_button.configure(state='disabled' if value or self.active else 'normal')
        self.refresh_button.configure(state='disabled' if value or self.active else 'normal')
        self.adapter.configure(state='disabled' if value or self.active else 'readonly')
        for field in (self.upstream,self.port):field.configure(state='disabled' if value or self.active else 'normal')

    def start(self):
        if self.busy or self.active:return
        index=self.adapter.current()
        if index<0:
            messagebox.showerror('Selecciona un adaptador','Selecciona Wi-Fi o Ethernet, según la conexión que utilizas.');return
        try:
            upstream=str(ipaddress.ip_address(self.upstream.get().strip()))
            if ipaddress.ip_address(upstream).is_loopback:
                raise ValueError('loopback')
            port=int(self.port.get())
            if not 1024<=port<=65535 or port==53:raise ValueError('puerto')
        except ValueError:
            messagebox.showerror('Configuración','Usa una IP externa de upstream y un puerto de panel entre 1024 y 65535.');return
        adapter=dict(self.adapter_list[index]);self.web_port=port
        self.set_busy(True);self.phase='starting';self.message.set('Iniciando y comprobando DNS/HTTPS. Después Windows solicitará permisos…')
        self.background(lambda:self.start_worker(adapter,upstream,port))

    def start_worker(self,adapter,upstream,port):
        if not (ROOT/'instance/tls/server-cert.pem').is_file():
            raise ProtectionError('Falta la configuración HTTPS inicial. Sigue INICIO_AUTOMATICO.md; no se modificó el DNS.')
        session=self.new_session()
        request={'run_id':session.name,'token':secrets.token_hex(32),'adapter_guid':adapter['guid'],
                 'controller_pid':os.getpid(),'server_pid':0,'ipv6':adapter['ipv6'],'web_port':port}
        atomic_json(session/'request.json',request)
        server_python=Path(sys.executable).with_name('python.exe') if os.name=='nt' else Path(sys.executable)
        args=[str(server_python),str(ROOT/'run.py'),'--web-port',str(port),'--dns-port','53',
              '--upstream',upstream,'--launcher-session',str(session)]
        if adapter['ipv6']:args.append('--dns-ipv6-loopback')
        try:
            with (session/'server.log').open('wb') as log:
                self.server=subprocess.Popen(args,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,
                    creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            request['server_pid']=self.server.pid;atomic_json(session/'request.json',request)
            real_pid=wait_server_ready(self.server,session)
            if not healthy(request['token'],ipv6=adapter['ipv6']):
                raise ProtectionError('No se confirmó el DNS propio en ambas familias/transportes. El DNS no se cambió.')
            try:
                panel_ok=verified_panel(port)
            except ssl.SSLCertVerificationError as error:
                raise ProtectionError('La verificación HTTPS falló: ' + error.verify_message + '. Consulta CORRECCION_TLS.md. No se modificó el DNS.') from None
            except ssl.SSLError:
                raise ProtectionError('Windows no confía en el certificado local. Instala tu CA como indica INICIO_AUTOMATICO.md. No se modificó el DNS.') from None
            if not panel_ok:raise ProtectionError('El panel HTTPS no confirmó el inicio; no se modificó el DNS.')
            # No solicitar UAC ni anunciar protección sin confirmación del navegador.
            self.chrome_controller().enable(session)
            # Comprobar conectividad externa antes de redirigir el adaptador.
            import dns.query,dns.message,dns.rcode
            reply=dns.query.udp_with_fallback(dns.message.make_query('example.com','A'),upstream,timeout=3)[0]
            if reply.rcode()!=dns.rcode.NOERROR or not reply.answer:
                raise ProtectionError('El DNS externo no resolvió el dominio de comprobación. Revisa tu conexión o usa el DNS autorizado de tu red.')
            # En Windows el ejecutable del venv puede ser un intermediario con otro PID.
            # La firma de sesión y las sondas DNS/TLS anteriores validan al servidor real.
            request['server_pid']=real_pid
            atomic_json(session/'request.json',request)
            self.helper=elevate(sys.executable,[str(ROOT/'control_windows.py'),'--session',str(session)],ROOT)
            return ('waiting',None)
        except Exception:
            self.cleanup_unprotected()
            raise

    def cleanup_unprotected(self):
        if getattr(self,'chrome',None):self.chrome.disable()
        if not self.server or self.server.poll() is not None:return
        if self.session and (self.session/'request.json').exists():
            request=read_json(self.session/'request.json')
            atomic_json(self.session/'server-stop.json',{'token':request['token']})
        try:self.server.wait(timeout=5)
        except subprocess.TimeoutExpired:self.server.terminate()

    def open_panel(self):
        webbrowser.open(f'https://localhost:{self.web_port}')

    def stop(self):
        if not self.session:return
        request=read_json(self.session/'request.json')
        atomic_json(self.session/'stop.json',{'token':request['token']})
        self.phase='restoring';self.stop_button.configure(state='disabled');self.message.set('Restaurando el DNS original antes de detener el servidor…')

    def recover(self):
        if self.busy or self.active:return
        self.set_busy(True);self.phase='recovering';self.message.set('Windows solicitará permisos para restaurar el respaldo DNS guardado…')
        def job():
            self.chrome_controller().disable()
            session=self.new_session()
            self.helper=elevate(sys.executable,[str(ROOT/'control_windows.py'),'--session',str(session),'--restore-only'],ROOT)
            return ('waiting',None)
        self.background(job)

    def close(self):
        self.closing=True
        if self.active:self.stop()
        elif self.busy or self.phase in ('restoring','recovering','waiting'):self.message.set('Esperando a terminar la operación y restaurar el DNS…')
        elif self.phase=='restore_failed':
            self.closing=False
            messagebox.showwarning('Restauración pendiente','Reintenta Restaurar DNS guardado antes de cerrar. El respaldo se conserva.');return
        else:self.destroy()

    def destroy(self):
        if self.chrome:self.chrome.close()
        self.root.destroy()

    def finish_worker(self,phase,message):
        if self.chrome:
            try:
                self.chrome.disable()
                confirmed=self.chrome.wait(allow_absent=True)
                message += (' Chrome confirmó la retirada de reglas y la recarga de pestañas.' if confirmed
                            else ' Chrome está desconectado; confirma la conexión antes de volver a activar.')
            except (OSError,ProtectionError) as error:
                message += ' Chrome no confirmó la retirada de reglas: '+str(error)
        return ('finished',(phase,message))

    def poll(self):
        try:
            while True:
                kind,value=self.events.get_nowait()
                if kind=='error':
                    self.set_busy(False);self.phase='error';self.message.set(value)
                    messagebox.showerror('DNSentinel',value)
                elif value[0]=='adapters':
                    self.adapter_list=value[1]
                    self.adapter['values']=[f"{a['name']} · IPv4"+(' + IPv6' if a['ipv6'] else '') for a in self.adapter_list]
                    if len(self.adapter_list)==1:self.adapter.current(0)
                    self.message.set('Selecciona el adaptador y pulsa Iniciar protección. Se solicitarán permisos de administrador.')
                    try:
                        state=read_json(machine_state())
                        if state.get('phase')!='restored':self.message.set('Hay un respaldo pendiente: utiliza Restaurar DNS guardado antes de iniciar.')
                    except (OSError,ValueError):
                        self.message.set('Selecciona el adaptador y pulsa Iniciar protección.')
                elif value[0]=='finished':
                    phase,message=value[1]
                    self.active=False;self.phase=phase;self.set_busy(False)
                    self.stop_button.configure(state='disabled');self.panel_button.configure(state='disabled')
                    self.finished=self.finishing
                    self.message.set(message)
                    if phase in ('restored','error'):self.cleanup_unprotected()
                else:self.phase='waiting'
        except queue.Empty:
            pass
        if self.session and (self.session/'status.json').exists():
            try:
                status=read_json(self.session/'status.json');phase=status['phase']
                terminal=(self.session.name,phase)
                if terminal!=self.finished and terminal!=self.finishing:self.message.set(status['message'])
                if phase=='active' and self.phase!='restoring':
                    if not self.chrome or not self.chrome.synchronized():
                        self.chrome_pending=self.chrome_pending or time.monotonic()
                        self.message.set('Sincronizando reglas y pestañas de Chrome…')
                        if time.monotonic()-self.chrome_pending>4:
                            self.stop()
                            self.message.set('Chrome dejó de confirmar la protección. Restaurando DNS y retirando reglas…')
                        self.root.after(500,self.poll);return
                    self.chrome_pending=None
                    self.active=True;self.phase='active';self.set_busy(False)
                    self.message.set('Protección activa en DNS y Chrome. Reglas y pestañas sincronizadas.')
                    self.stop_button.configure(state='normal');self.panel_button.configure(state='normal')
                    if not self.opened:
                        self.opened=True;self.open_panel()
                    if self.closing:self.stop()
                elif phase in ('restored','restore_failed','error'):
                    if terminal!=self.finishing:
                        self.finishing=terminal
                        self.active=False;self.phase='chrome_restoring';self.set_busy(True)
                        self.message.set(status['message']+' Retirando reglas de Chrome…')
                        self.background(lambda:self.finish_worker(phase,status['message']))
            except (OSError,ValueError,KeyError):
                self.message.set('No se pudo leer el estado local. Si necesitas parar, utiliza Detener protección; conserva el respaldo.')
                if self.helper and self.helper.alive() and self.phase!='restoring' and (self.session/'request.json').exists():
                    self.stop_button.configure(state='normal')
        # El supervisor suele dejar el estado final tras un cierre inesperado del helper.
        if self.helper and not self.helper.alive() and self.phase=='waiting':
            self.message.set('El componente de red terminó. Espera la recuperación o utiliza Restaurar DNS guardado.')
            self.set_busy(False)
        if self.helper and not self.helper.alive() and self.phase in ('restored','error','restore_failed'):
            self.helper.close();self.helper=None
        if self.closing and not self.busy and not self.active and self.phase in ('restored','error','idle'):
            self.destroy();return
        self.root.after(500,self.poll)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--recover',action='store_true')
    args=parser.parse_args();root=tk.Tk();Launcher(root,args.recover);root.mainloop()


if __name__=='__main__':main()
