"""Pruebas del registro de auditoría común (RS4)."""

from __future__ import annotations

import json

from src.common.auditoria import registrar_evento


def test_registrar_evento_escribe_campos(tmp_path):
    ruta = tmp_path / "accesos.jsonl"
    registrar_evento("login_succeeded", outcome="success", username="u1",
                     device_id="d1", source="RF2", ruta=ruta)
    lineas = ruta.read_text(encoding="utf-8").strip().splitlines()
    assert len(lineas) == 1
    registro = json.loads(lineas[0])
    assert registro["event"] == "login_succeeded"
    assert registro["outcome"] == "success"
    assert registro["username"] == "u1"
    assert registro["device_id"] == "d1"
    assert registro["source"] == "RF2"
    assert "timestamp" in registro


def test_registrar_evento_descarta_campos_sensibles(tmp_path):
    ruta = tmp_path / "accesos.jsonl"
    registrar_evento("login_failed", outcome="failure", username="u1",
                     reason="credenciales", source="RF2", ruta=ruta,
                     password="SECRETO", token="TOKEN", nonce="NONCE")
    registro = json.loads(ruta.read_text(encoding="utf-8").strip())
    assert registro["reason"] == "credenciales"
    assert "password" not in registro
    assert "token" not in registro
    assert "nonce" not in registro
    # Y por si acaso, el secreto no aparece en ninguna parte de la línea.
    assert "SECRETO" not in ruta.read_text(encoding="utf-8")


def test_registrar_evento_sin_identidad_usa_guion(tmp_path):
    ruta = tmp_path / "accesos.jsonl"
    registrar_evento("login_failed", outcome="failure", source="RF2", ruta=ruta)
    registro = json.loads(ruta.read_text(encoding="utf-8").strip())
    assert registro["username"] == "-"
    assert registro["device_id"] == "-"
