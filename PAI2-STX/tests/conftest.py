"""Salida legible de las pruebas cuando se ejecutan con ``pytest -s``."""

from __future__ import annotations

import pytest


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
