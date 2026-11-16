"""Arranque con los mismos comandos de instalación del usuario, en copia aislada."""
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import time

from setup_tls import create_certificate


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        return sock.getsockname()[1]


def test_run_cli_https_and_dns(tmp_path):
    root = tmp_path/'project'
    source = Path(__file__).resolve().parents[1]
    shutil.copytree(source/'dnsentinel', root/'dnsentinel', ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copytree(source/'desktop', root/'desktop', ignore=shutil.ignore_patterns('__pycache__'))
    for name in ['run.py','check_dns.py']:
        shutil.copy2(source/name, root/name)
    env = {**os.environ, 'DNSENTINEL_KEY_FILE':str(tmp_path/'data.key')}
    env['PYTHONIOENCODING']='utf-8'
    password = secrets.token_urlsafe(24)
    # getpass de Windows lee la consola física aun con stdin redirigido.
    # Un wrapper de stdin fuerza su modo por tubería en este subprocess de prueba.
    cli = [sys.executable,'-c',
           'import io,sys; sys.stdin=io.TextIOWrapper(sys.stdin.buffer,encoding="utf-8"); from flask.cli import main; main()',
           '--app','dnsentinel:create_app','create-user','admin']
    result = subprocess.run(cli,
                            input=password+'\n'+password+'\n', text=True, capture_output=True, cwd=root, env=env, timeout=20)
    assert result.returncode == 0 and password not in result.stdout
    result = subprocess.run([sys.executable,'-m','flask','--app','dnsentinel:create_app','seed-demo'],
                            text=True,capture_output=True,cwd=root,env=env,timeout=20)
    assert result.returncode == 0
    ca = create_certificate(root/'instance/tls')
    web_port,dns_port = free_port(),free_port()
    process = subprocess.Popen([sys.executable,'run.py','--web-port',str(web_port),'--dns-port',str(dns_port)],
                                stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,cwd=root,env=env)
    connection = http.client.HTTPSConnection('localhost',web_port,context=ssl.create_default_context(cafile=str(ca)),timeout=2)
    try:
        ready = False
        for _ in range(100):
            if process.poll() is not None:
                raise AssertionError('El proceso no inició: '+process.stderr.read())
            try:
                connection.request('GET','/login')
                response = connection.getresponse()
                ready = response.status == 200
                response.read()
                break
            except (OSError,http.client.HTTPException):
                connection.close()
                time.sleep(.05)
        assert ready
        for transport in [[],['--tcp']]:
            result = subprocess.run([sys.executable,'check_dns.py','malware.test','--port',str(dns_port),*transport],
                                     capture_output=True,text=True,cwd=root,env=env,timeout=10)
            assert result.returncode == 0
            assert json.loads(result.stdout)['rcode'] == 'REFUSED'
    finally:
        connection.close()
        process.terminate()
        process.communicate(timeout=15)


def test_launcher_server_lifecycle_stops_only_on_matching_token(tmp_path):
    from desktop.core import atomic_json
    from desktop.probe import healthy
    # La prueba solo usa sockets loopback; nunca configura el DNS del equipo.
    dns_port=free_port()
    root=tmp_path/'project';source=Path(__file__).resolve().parents[1]
    for package in ['dnsentinel','desktop']:
        shutil.copytree(source/package,root/package,ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copy2(source/'run.py',root/'run.py')
    create_certificate(root/'instance/tls')
    session=root/'instance/launcher/test';session.mkdir(parents=True)
    token=secrets.token_hex(32)
    atomic_json(session/'request.json',{'token':token})
    env={**os.environ,'DNSENTINEL_KEY_FILE':str(tmp_path/'data.key')}
    process=subprocess.Popen([sys.executable,'run.py','--dns-port',str(dns_port),'--web-port',str(free_port()),'--launcher-session',str(session)],
                             cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        for _ in range(100):
            if process.poll() is not None:raise AssertionError(process.stderr.read())
            if (session/'server-ready.json').exists():break
            time.sleep(.05)
        from launcher import wait_server_ready
        ready=read_json_local(session/'server-ready.json')
        # El venv Windows puede crear un proceso intermediario con otro PID.
        atomic_json(session/'request.json',{'token':token,'web_port':ready['port']})
        assert wait_server_ready(process,session,timeout=1)==ready['pid']
        assert (session/'chrome-policy.json').is_file()
        assert healthy(token,port=dns_port,ipv6=False)
        atomic_json(session/'server-stop.json',{'token':secrets.token_hex(32)})
        time.sleep(.7)
        assert process.poll() is None
        atomic_json(session/'server-stop.json',{'token':token})
        process.communicate(timeout=15)
        assert process.returncode==0
    finally:
        if process.poll() is None:
            atomic_json(session/'server-stop.json',{'token':token})
            process.communicate(timeout=10)


def read_json_local(path):
    return json.loads(path.read_text())
