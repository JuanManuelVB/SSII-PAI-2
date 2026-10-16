"""Demostración OPCIONAL PAI-2 (+10 %): TLS frente a suplantación.

SOLO en loopback (127.0.0.1), no ataca servicios externos, no escribe
claves privadas fuera del directorio temporal y no imprime secretos.

python -m tools.ataque_opcional
"""
from __future__ import annotations

import json
import socket
import ssl
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _certificado_ca(cn):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    now=datetime.now(timezone.utc)
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,cn)])
    crt=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=2))
         .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
         .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,
                         key_encipherment=False,data_encipherment=False,key_agreement=False,
                         key_cert_sign=True,crl_sign=True,encipher_only=False,decipher_only=False),critical=True)
         .sign(key,hashes.SHA256()))
    return key,crt


def _emitir(issuer_key,issuer_crt,cn,client=False):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    now=datetime.now(timezone.utc)
    builder=(x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,cn)]))
        .issuer_name(issuer_crt.subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH]),critical=False))
    if not client:
        builder=builder.add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),critical=False)
    return key,builder.sign(issuer_key,hashes.SHA256())


def _save_key(path,key):
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    path.chmod(0o600)


def _save_cert(path,cert):
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def probar_escenario(ca_buena,servidor_cert,servidor_key, *, mtls=False, version_antigua=False):
    """Demostrar que handshake TLS falso/no autorizado no permite datos HTTP."""
    result={'server_rejected':False,'client_rejected':False,'payload_delivered':False}
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as listening:
        listening.bind(('127.0.0.1',0)); listening.listen(1)
        port=listening.getsockname()[1]
        def server():
            try:
                con,_=listening.accept()
                with con:
                    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ctx.minimum_version=ssl.TLSVersion.TLSv1_3
                    ctx.maximum_version=ssl.TLSVersion.TLSv1_3
                    ctx.load_cert_chain(str(servidor_cert),str(servidor_key))
                    if mtls:
                        ctx.verify_mode=ssl.CERT_REQUIRED
                        ctx.load_verify_locations(cafile=str(ca_buena))
                    try:
                        with ctx.wrap_socket(con,server_side=True) as ssl_sock:
                            result['payload_delivered']=bool(ssl_sock.recv(1024))
                    except ssl.SSLError:
                        result['server_rejected']=True
            except OSError:
                result['server_rejected']=True
        thread=threading.Thread(target=server,daemon=True); thread.start()
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname=True
        ctx.verify_mode=ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=str(ca_buena))
        if version_antigua:
            ctx.maximum_version=ssl.TLSVersion.TLSv1_2
        else:
            ctx.minimum_version=ssl.TLSVersion.TLSv1_3
        try:
            with socket.create_connection(('127.0.0.1',port),timeout=4) as sock:
                with ctx.wrap_socket(sock,server_hostname='localhost') as tls:
                    tls.settimeout(4)
                    tls.sendall(b'CREDENCIALES_DE_PRUEBA_NO_REALES')
                    tls.recv(16)
        except (ssl.SSLError, ConnectionError, TimeoutError, OSError):
            result['client_rejected']=True
        thread.join(5)
    return result


def ejecutar():
    with tempfile.TemporaryDirectory(prefix='pai2-opt-') as temp:
        d=Path(temp)
        key_ca,cert_ca=_certificado_ca('Universidad U-Secure LAB')
        rogue_key,rogue_ca=_certificado_ca('Falsa CA del atacante')
        key_good,cert_good=_emitir(key_ca,cert_ca,'localhost')
        key_fake,cert_fake=_emitir(rogue_key,rogue_ca,'localhost')
        ca=d/'ca.pem';_save_cert(ca,cert_ca)
        goodcrt=d/'good.crt';goodkey=d/'good.key';_save_cert(goodcrt,cert_good);_save_key(goodkey,key_good)
        fakecrt=d/'fake.crt';fakekey=d/'fake.key';_save_cert(fakecrt,cert_fake);_save_key(fakekey,key_fake)
        pruebas={
           'suplantacion_servidor_ca_desconocida': probar_escenario(ca,fakecrt,fakekey),
           'cliente_sin_certificado_mtls': probar_escenario(ca,goodcrt,goodkey,mtls=True),
           'cliente_tls_1_2_obsoleto': probar_escenario(ca,goodcrt,goodkey,version_antigua=True),
        }
    resultados={n:bool(r['client_rejected'] and not r['payload_delivered']) for n,r in pruebas.items()}
    documento={
        'timestamp_utc':datetime.now(timezone.utc).isoformat(),
        'entorno':'127.0.0.1, certificados efimeros, datos ficticios',
        'pruebas':resultados,
        'detalle':pruebas,
        'aviso':'Esta es una prueba de propiedades TLS en loopback; no demuestra por sí sola la protección del túnel OpenVPN en una red real.',
    }
    ruta=Path('evidencias/ataques/tls_opcional.json')
    ruta.parent.mkdir(parents=True,exist_ok=True)
    ruta.write_text(json.dumps(documento,indent=2,ensure_ascii=False),encoding='utf-8')
    print(json.dumps(resultados,ensure_ascii=False,indent=2))
    if not all(resultados.values()):
        raise SystemExit('FALLO: no se ha demostrado el rechazo en alguna prueba')
    print('Pruebas TLS negativas superadas. Evidencia:',ruta)
    return documento


if __name__=='__main__':
    ejecutar()
