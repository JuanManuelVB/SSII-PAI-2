# PKI de BYODSEC (camino A)

La CA corporativa firma los certificados X.509 del servidor de HTTPS y de cada dispositivo BYOD.

- `pki/ca/ca.crt` — certificado público de la CA.
- `pki/ca/ca.key` — **clave privada** de la CA, solo local y nunca incluida en ZIP.
- `pki/server/server.crt` / `server.key` — identidad del servidor TLS 1.3.
- `pki/clients/` — pares de identidad por dispositivo, vinculados a usuarios en SQLite.
- `pki/clients/rf5/credenciales.csv` — contraseñas de laboratorio creadas localmente; no distribuir.

Desde WSL y en la raíz del proyecto: `bash laboratorio.sh preparar` genera el material solo si falta y precarga 300 identidades de laboratorio. Si ya tienes una CA y usuarios activos, **conserva su base de datos y sus claves**. No sustituyas CA o certificado del servidor por otros arbitrarios.

Para emitir un certificado adicional a un usuario existente utiliza la opción **2 — Generar certificado** en el cliente Windows: el cliente crea una clave RSA 3072 local y envía solo su clave pública al servidor de registro HTTPS `8444`. La CA firma el certificado y SQLite registra el emparejamiento. Para entrar después usa el puerto `9443` que exige mTLS.

La autenticación tiene dos capas: (1) certificado del dispositivo válido y reconocido, (2) contraseña corporativa correcta más desafío firmado.

Las claves de este laboratorio están sin cifrar en reposo para facilitar demostraciones; en producción deberían cifrarse y aislarse.
