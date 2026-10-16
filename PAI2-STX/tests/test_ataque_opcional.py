from tools.ataque_opcional import ejecutar

def test_ataque_controlado_local(tmp_path,monkeypatch):
    monkeypatch.chdir(tmp_path)
    documento=ejecutar()
    assert all(documento['pruebas'].values())
    assert (tmp_path/'evidencias/ataques/tls_opcional.json').exists()
