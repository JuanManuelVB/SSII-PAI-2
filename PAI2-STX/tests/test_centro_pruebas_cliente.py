"""Validación del código del centro de pruebas, no sustituye la demo real usuario->WSL."""
from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.client import laboratorio
from src.client.servicio_consola import ErrorConsola


def test_creacion_de_usuario_valida_y_delega_en_wsl(monkeypatch):
    observado = {}
    def fake_ejec(modulo, argumentos, **kwargs):
        observado['modulo'] = modulo
        observado['argumentos'] = argumentos
        observado['interactivo'] = kwargs['interactivo']
        return subprocess.CompletedProcess([], 0)
    monkeypatch.setattr(laboratorio, 'ejecutar_en_wsl', fake_ejec)
    assert laboratorio.crear_usuario_corporativo('usuario_demo', 'PDI')
    assert observado == {'modulo':'src.server.usuarios',
                         'argumentos':['crear','usuario_demo','PDI'], 'interactivo':True}


@pytest.mark.parametrize('nombre,rol', [('x','PDI'),('../foo','PDI'),('demo','ADMIN'),('a;rm','PAS')])
def test_creacion_rechaza_argumentos_invalidos(nombre,rol):
    with pytest.raises(ErrorConsola):
        laboratorio.crear_usuario_corporativo(nombre, rol)


def test_wsl_comando_parametros_no_entran_en_shell(monkeypatch):
    monkeypatch.setattr(laboratorio.os, 'name', 'nt', raising=False)
    monkeypatch.setattr(laboratorio.shutil, 'which', lambda nombre: 'wsl.exe')
    llamadas = []
    def fake_run(cmd, **kwargs):
        llamadas.append(cmd)
        if cmd[2] == 'wslpath':
            return subprocess.CompletedProcess(cmd, 0, stdout='/mnt/c/proyecto con espacios\n')
        return subprocess.CompletedProcess(cmd, 0, stdout='ok')
    monkeypatch.setattr(laboratorio.subprocess, 'run', fake_run)
    resultado = laboratorio.ejecutar_en_wsl('src.server.usuarios', ['crear', 'demo', 'PDI'])
    assert resultado.returncode == 0
    assert llamadas[1][-4:] == ['src.server.usuarios', 'crear', 'demo', 'PDI']
    assert llamadas[1][6] == '/mnt/c/proyecto con espacios'


def test_enumeracion_tshark(monkeypatch):
    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd,0,stdout='1. \\Device\\NPF_Loopback (Adapter for loopback traffic capture)\n2. Ethernet\n')
    monkeypatch.setattr(laboratorio.subprocess, 'run', fake_run)
    assert laboratorio.interfaces_captura(Path('tshark.exe'))[0][0] == '1'


def test_captura_no_inicia_si_no_esta_tshark(monkeypatch):
    monkeypatch.setattr(laboratorio, 'buscar_tshark', lambda: None)
    with pytest.raises(ErrorConsola):
        laboratorio.CapturaTLS().iniciar('1')
