"""La lógica de red se prueba con un adaptador simulado, sin cambiar el equipo."""
import copy
import secrets
import socket
import uuid

import pytest

from desktop.core import NetworkProtection, ProtectionError, atomic_json, read_json, managed_config
from desktop.probe import healthy
from dnsentinel import create_app
from dnsentinel.dns_server import DNSService


class Adapter:
    def __init__(self,ipv6=True):
        self.data={'guid':str(uuid.uuid4()),'index':7,'name':'Wi-Fi prueba','ipv6':ipv6,'up':True}
        self.config={4:{'source':'automatic','addresses':[]},6:{'source':'static','addresses':['2001:db8::53','2001:db8::54']}}
        self.calls=[];self.fail_family=None
    def adapter(self,guid):
        if guid!=self.data['guid']:raise ProtectionError('Adaptador no encontrado')
        return self.data
    def snapshot(self,adapter,family):return copy.deepcopy(self.config[family])
    def apply(self,adapter,family,value):
        self.calls.append((family,copy.deepcopy(value)))
        if self.fail_family==family:raise ProtectionError('Error de red simulado')
        self.config[family]=copy.deepcopy(value)
    def flush(self):return None


@pytest.fixture
def protection(tmp_path):
    return NetworkProtection(Adapter(),tmp_path/'state.json')


def prepare(protection):
    run_id=str(uuid.uuid4())
    protection.prepare(protection.backend.data['guid'],run_id)
    return run_id


def test_backup_before_changes_and_exact_automatic_static_restore(protection):
    original=copy.deepcopy(protection.backend.config)
    run=prepare(protection)
    assert protection.state()['phase']=='saved' and not protection.backend.calls
    assert protection.state()['original']=={'4':original[4],'6':original[6]}
    protection.activate(run)
    assert protection.backend.config=={4:managed_config(4),6:managed_config(6)}
    # Simula otra instancia posterior: el respaldo persistente basta para recuperar.
    recovery=NetworkProtection(protection.backend,protection.state_file)
    recovery.restore(run)
    assert protection.backend.config==original
    assert recovery.state()['phase']=='restored'
    calls=len(protection.backend.calls)
    recovery.restore(run)
    assert len(protection.backend.calls)==calls


def test_partial_activation_rolls_back_using_saved_backup(protection):
    original=copy.deepcopy(protection.backend.config);run=prepare(protection)
    protection.backend.fail_family=6
    with pytest.raises(ProtectionError):protection.activate(run)
    assert protection.backend.config[4]==managed_config(4)
    assert protection.state()['phase']=='saved'
    protection.restore(run)  # IPv6 no se cambió: no necesita ejecutar su setter fallido.
    assert protection.backend.config==original


def test_restore_failure_preserves_backup_and_can_retry(protection):
    run=prepare(protection);protection.activate(run)
    protection.backend.fail_family=4
    with pytest.raises(ProtectionError):protection.restore(run)
    assert protection.state()['phase']=='restore_failed'
    protection.backend.fail_family=None
    protection.restore(run)
    assert protection.state()['phase']=='restored'
    assert protection.backend.config[4]['source']=='automatic'


def test_never_overwrites_pending_backup_or_other_session(protection):
    run=prepare(protection)
    with pytest.raises(ProtectionError):prepare(protection)
    with pytest.raises(ProtectionError):protection.activate(str(uuid.uuid4()))
    with pytest.raises(ProtectionError):protection.restore(str(uuid.uuid4()))
    assert protection.state()['run_id']==run and not protection.backend.calls


def test_external_change_is_not_overwritten(protection):
    run=prepare(protection);protection.activate(run)
    other={'source':'static','addresses':['192.0.2.53']}
    protection.backend.config[4]=copy.deepcopy(other)
    with pytest.raises(ProtectionError):protection.restore(run)
    assert protection.backend.config[4]==other
    assert protection.state()['phase']=='restore_failed'


def test_no_activation_if_dns_changes_between_backup_and_start(protection):
    run=prepare(protection)
    protection.backend.config[4]={'source':'static','addresses':['192.0.2.53']}
    with pytest.raises(ProtectionError):protection.activate(run)
    assert not protection.backend.calls


def test_loopback_original_requires_manual_recovery(protection):
    protection.backend.config[4]=managed_config(4)
    with pytest.raises(ProtectionError):prepare(protection)
    assert not protection.state_file.exists() and not protection.backend.calls


def test_only_selected_adapter_and_enabled_family_are_changed(tmp_path):
    backend=Adapter(ipv6=False)
    protection=NetworkProtection(backend,tmp_path/'state.json')
    run=prepare(protection);protection.activate(run);protection.restore(run)
    assert all(family==4 for family,_ in backend.calls)


def test_backup_write_failure_prevents_network_change(protection,monkeypatch):
    def fail(*args):raise OSError('No se puede guardar')
    monkeypatch.setattr('desktop.core.atomic_json',fail)
    with pytest.raises(OSError):prepare(protection)
    assert not protection.backend.calls


def test_invalid_addresses_in_backup_are_rejected(protection):
    prepare(protection)
    state=read_json(protection.state_file)
    state['original']['4']['addresses']=['127.0.0.1 & command']
    state['original']['4']['source']='static'
    atomic_json(protection.state_file,state)
    with pytest.raises(ValueError):protection.restore()
    assert not protection.backend.calls


def test_own_server_health_dual_stack_does_not_forward_or_record(tmp_path):
    if not socket.has_ipv6:pytest.skip('IPv6 no disponible')
    with socket.socket(socket.AF_INET6) as sock:
        try:sock.bind(('::1',0))
        except OSError:pytest.skip('Loopback IPv6 no disponible')
        port=sock.getsockname()[1]
    token=secrets.token_hex(32)
    app=create_app({'TESTING':True,'DATABASE':str(tmp_path/'dns.sqlite3'),'DATA_KEY':secrets.token_bytes(32),
                    'RATE_KEY':secrets.token_bytes(32),'LAUNCHER_HEALTH_TOKEN':token})
    server=DNSService(app,port=port,additional_hosts=('::1',),upstream='192.0.2.1',timeout=.1)
    server.start()
    try:
        assert healthy(token,port,ipv6=True)
        assert not healthy(secrets.token_hex(32),port,ipv6=True)
        assert server.status['processed']==0  # no se contaminaron los logs de consultas.
    finally:server.stop()


def test_netsh_arguments_restore_servers_in_order_without_shell(monkeypatch):
    import desktop.windows as windows
    calls=[]
    monkeypatch.setattr(windows,'system_exe',lambda name:'C:/Windows/System32/'+name)
    monkeypatch.setattr(windows,'command',lambda args,**kwargs:calls.append(args))
    backend=windows.WindowsDNS()
    adapter={'index':7,'name':'Wi-Fi & texto que no se ejecuta'}
    backend.apply(adapter,4,{'source':'static','addresses':['192.0.2.53','192.0.2.54']})
    backend.apply(adapter,6,{'source':'automatic','addresses':[]})
    assert len(calls)==3
    assert calls[0][1:]==['interface','ipv4','set','dnsservers','name=7','source=static','address=192.0.2.53','validate=no']
    assert calls[1][1:]==['interface','ipv4','add','dnsservers','name=7','address=192.0.2.54','index=2','validate=no']
    assert calls[2][-1]=='source=dhcp'
    with pytest.raises(ValueError):backend.apply(adapter,4,{'source':'static','addresses':['127.0.0.1 & calc']})
    assert len(calls)==3


def test_watchdog_restores_after_controller_dies(protection,tmp_path,monkeypatch):
    import control_windows as control
    run=prepare(protection);protection.activate(run)
    class Handle:
        def __init__(self,pid):self.pid=pid
        def alive(self):return self.pid!=101
        def close(self):return None
    monkeypatch.setattr(control,'Process',Handle)
    request={'controller_pid':101,'server_pid':202,'run_id':run,'token':secrets.token_hex(32)}
    control.watchdog(tmp_path,request,303,protection)
    assert protection.state()['phase']=='restored'
    assert read_json(tmp_path/'status.json')['phase']=='restored'
    assert read_json(tmp_path/'server-stop.json')['token']==request['token']


def test_watchdog_preserves_backup_and_keeps_server_if_restore_fails(protection,tmp_path,monkeypatch):
    import control_windows as control
    run=prepare(protection);protection.activate(run);protection.backend.fail_family=4
    class Handle:
        def __init__(self,pid):return None
        def alive(self):return False
        def close(self):return None
    monkeypatch.setattr(control,'Process',Handle);monkeypatch.setattr(control.time,'sleep',lambda seconds:None)
    request={'controller_pid':101,'server_pid':202,'run_id':run,'token':secrets.token_hex(32)}
    control.watchdog(tmp_path,request,303,protection)
    assert protection.state()['phase']=='restore_failed'
    assert read_json(tmp_path/'status.json')['phase']=='restore_failed'
    assert not (tmp_path/'server-stop.json').exists()


def test_gui_worker_cleans_up_server_if_uac_cancelled(tmp_path,monkeypatch):
    import launcher
    import dns.query,dns.rcode
    monkeypatch.setattr(launcher,'ROOT',tmp_path)
    monkeypatch.setattr(launcher,'prepare_session_access',lambda path:None)
    (tmp_path/'instance/tls').mkdir(parents=True)
    (tmp_path/'instance/tls/server-cert.pem').write_text('placeholder de presencia, sin certificado real')
    class Child:
        def __init__(self,args,**kwargs):
            self.pid=123;self.stopped=False
            session=__import__('pathlib').Path(args[args.index('--launcher-session')+1])
            atomic_json(session/'server-ready.json',{'pid':self.pid})
        def poll(self):return 0 if self.stopped else None
        def wait(self,timeout):self.stopped=True
        def terminate(self):self.stopped=True
    monkeypatch.setattr(launcher.subprocess,'Popen',Child)
    monkeypatch.setattr(launcher,'healthy',lambda *args,**kwargs:True)
    monkeypatch.setattr(launcher,'verified_panel',lambda port:True)
    monkeypatch.setattr(launcher,'wait_server_ready',lambda *args:123)
    class Chrome:
        def enable(self,session):return None
        def disable(self):return None
    monkeypatch.setattr(launcher.Launcher,'chrome_controller',lambda self:Chrome())
    class Reply:
        answer=True
        def rcode(self):return dns.rcode.NOERROR
    monkeypatch.setattr(dns.query,'udp_with_fallback',lambda *args,**kwargs:(Reply(),False))
    def deny(*args):raise ProtectionError('UAC cancelado')
    monkeypatch.setattr(launcher,'elevate',deny)
    window=launcher.Launcher.__new__(launcher.Launcher)
    window.session=None;window.server=None;window.helper=None;window.opened=False
    with pytest.raises(ProtectionError,match='UAC cancelado'):
        window.start_worker({'guid':str(uuid.uuid4()),'ipv6':False},'1.1.1.1',8444)
    assert window.server.stopped
    assert read_json(window.session/'server-stop.json')['token']==read_json(window.session/'request.json')['token']


def test_no_dns_activation_without_chrome_confirmation(tmp_path,monkeypatch):
    import launcher
    monkeypatch.setattr(launcher,'ROOT',tmp_path)
    monkeypatch.setattr(launcher,'prepare_session_access',lambda path:None)
    (tmp_path/'instance/tls').mkdir(parents=True)
    (tmp_path/'instance/tls/server-cert.pem').write_text('presencia para prueba')
    class Child:
        pid=123
        stopped=False
        def __init__(self,*args,**kwargs):pass
        def poll(self):return 0 if self.stopped else None
        def wait(self,timeout):self.stopped=True
    class Chrome:
        def enable(self,session):raise ProtectionError('Chrome no confirmó')
        def disable(self):pass
    elevated=[]
    monkeypatch.setattr(launcher.subprocess,'Popen',Child)
    monkeypatch.setattr(launcher,'wait_server_ready',lambda *args:123)
    monkeypatch.setattr(launcher,'healthy',lambda *args,**kwargs:True)
    monkeypatch.setattr(launcher,'verified_panel',lambda port:True)
    monkeypatch.setattr(launcher.Launcher,'chrome_controller',lambda self:Chrome())
    monkeypatch.setattr(launcher,'elevate',lambda *args:elevated.append(args))
    window=launcher.Launcher.__new__(launcher.Launcher)
    window.session=None;window.server=None;window.helper=None;window.opened=False
    with pytest.raises(ProtectionError,match='Chrome no confirmó'):
        window.start_worker({'guid':str(uuid.uuid4()),'ipv6':False},'1.1.1.1',8444)
    assert not elevated and window.server.stopped
