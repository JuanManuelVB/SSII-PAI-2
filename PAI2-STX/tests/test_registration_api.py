from fastapi.testclient import TestClient

from src.server import app as server


def test_health_endpoint():
    print("[API] Consultando /health para comprobar que la aplicación responde")
    with TestClient(server.app) as client:
        response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    print("[API] /health respondió 200 y status=ok")


def test_registration_rejects_invalid_credentials():
    print("[RF1] Enviando un registro con credenciales inválidas")
    with TestClient(server.app) as client:
        response = client.post(
            "/api/v1/devices/register",
            json={
                "username": "unknown",
                "password": "a-strong-password",
                "device_id": "device-1",
                "public_key": "x" * 64,
            },
        )
    assert response.status_code == 401
    print("[RF1] Registro rechazado con HTTP 401")
