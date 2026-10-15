# PKI de PAI2-STX

## Qué es la PKI

Una PKI (Public Key Infrastructure) permite comprobar identidades mediante
certificados X.509:

```text
CA corporativa
    ├── certificado del gateway VPN
    └── certificados de clientes BYOD
```

La CA firma los certificados. Un cliente confía en un certificado porque puede
validar su firma hasta la CA que conoce de antemano. La clave privada asociada
al certificado nunca se comparte.

En mTLS se validan los dos extremos:

1. El cliente valida el certificado del gateway.
2. El gateway solicita y valida el certificado del cliente.

Eso evita depender únicamente de una contraseña robada. Para el requisito RF2,
el certificado del dispositivo será la primera capa y usuario/contraseña la
segunda capa.

## Preparar la PKI de laboratorio

Desde `PAI2-STX`:

```powershell
python -m pki.scripts.pki crear-ca
python -m pki.scripts.pki emitir-servidor
python -m pki.scripts.pki emitir-cliente pdi001
python -m pki.scripts.pki emitir-cliente pas001
python -m pki.scripts.pki verificar pki/clients/pdi001/pdi001.crt
```

La CA se crea una sola vez y el comando no la sobrescribe. Para revocar:

```powershell
python -m pki.scripts.pki revocar pki/clients/pdi001/pdi001.crt
python -m pki.scripts.pki verificar pki/clients/pdi001/pdi001.crt
```

El segundo `verificar` debe imprimir `REVOCADO/INVÁLIDO`. La CRL queda en
`pki/ca/ca.crl.pem` y el inventario local de seriales revocados en
`pki/ca/revoked.json`.

## Seguridad

Las claves privadas y certificados generados están ignorados por Git. La PKI
creada aquí es para laboratorio; en producción la clave privada de la CA debe
estar protegida por HSM o, como mínimo, cifrada y separada del gateway.
