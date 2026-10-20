"""Configuración común de pytest.

* Aísla cada prueba: ninguna escribe en ``data/``, ``pki/`` ni ``evidencias/``
  del proyecto (se redirigen a ``tmp_path``) y se ignoran las variables
  ``BYODSEC_*`` del laboratorio para no hablar con un Access Server real.
* Muestra el inicio y resultado de cada escenario con ``pytest -s``.
"""

from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def aislar_entorno(monkeypatch, tmp_path):
    for variable in list(os.environ):
        if variable.startswith("BYODSEC_"):
            monkeypatch.delenv(variable)
    import src.rf2.rutas as rutas_rf2
    import src.rf4.auditoria as auditoria_rf4
    import src.rf4.rutas as rutas_rf4
    import src.server.app as rf1

    monkeypatch.setattr(rf1, "RUTA_BASE_DATOS", tmp_path / "rf1-aislada.sqlite3")
    monkeypatch.setattr(rf1, "RUTA_AUDITORIA", tmp_path / "rf1-audit.jsonl")
    monkeypatch.setattr(rutas_rf2, "RUTA_AUDITORIA_ACCESOS", tmp_path / "accesos-audit.jsonl")
    for modulo in (auditoria_rf4, rutas_rf4):
        monkeypatch.setattr(modulo, "RUTA_AUDITORIA", tmp_path / "rf4-audit.jsonl")


def pytest_runtest_logstart(nodeid: str, location) -> None:
    """Anuncia qué escenario empieza, sin mostrar credenciales ni secretos."""
    print(f"\n[INICIO] {nodeid}")


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Muestra el resultado de cada fase de cada prueba."""
    resultado = yield
    informe = resultado.get_result()
    if informe.when == "call":
        print(f"[RESULTADO] {item.nodeid}: {informe.outcome.upper()}")
