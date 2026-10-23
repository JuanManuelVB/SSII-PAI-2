"""Genera un informe HTML autónomo (sin Internet ni librerías adicionales) de RS3.

Lee bench/resultados/comparativa*.json, incluidos ensayos antiguos, y muestra
SOLO las pruebas con 300 usuarios (sin borrar resultados de otras cargas).
Los ensayos incompletos no aportan métricas a las gráficas de rendimiento.
Uso:
  python -m tools.informe_rs3
  python -m tools.informe_rs3 --directorio bench/resultados --salida bench/resultados/informe_rs3.html
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime
from html import escape
import json
import math
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
ESCENARIOS = ("cifrado_tls13_mtls", "directo_sin_cifrar")
AZUL = "#4769ef"
VERDE = "#15ab9b"
ROJO = "#e17b56"


def _numero(v):
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
        return None
    return float(v)


def _texto_num(v, dec=1):
    x = _numero(v)
    if x is None:
        return "—"
    return f"{x:,.{dec}f}".replace(",", "·").replace(".", ",").replace("·", ".")


def _correcto(escenario: dict, solicitados: int) -> bool:
    return (isinstance(escenario, dict)
            and escenario.get("errores") == 0
            and escenario.get("mensajes_confirmados") == solicitados
            and solicitados > 0
            and _numero(escenario.get("throughput_mensajes_por_s")) is not None
            and _numero(escenario.get("latencia_mensaje_ms", {}).get("media")) is not None)


def _extraer_corridas(doc: dict, archivo: Path) -> list[dict]:
    if "corridas" in doc:
        vueltas = doc["corridas"]
        usuarios = doc.get("usuarios")
        mensajes = doc.get("mensajes_por_usuario_y_escenario")
        tamano = doc.get("bytes_por_mensaje")
        tipo = "actual"
    elif "escenarios" in doc:
        vueltas = [{"repeticion": 1, "escenarios": doc["escenarios"]}]
        usuarios = doc.get("usuarios_concurrentes")
        mensajes = doc.get("mensajes_por_usuario")
        tamano = doc.get("bytes_mensaje")
        tipo = "legado"
    else:
        return []
    if not all(isinstance(v, int) and v > 0 for v in (usuarios, mensajes, tamano)):
        return []
    resultado = []
    for vuelta in vueltas:
        if not isinstance(vuelta, dict):
            continue
        e = vuelta.get("escenarios", {})
        t = e.get(ESCENARIOS[0], {})
        h = e.get(ESCENARIOS[1], {})
        if not isinstance(t, dict) or not isinstance(h, dict):
            continue
        solicitados = usuarios * mensajes
        valido = _correcto(t, solicitados) and _correcto(h, solicitados)
        lt = _numero(t.get("latencia_mensaje_ms", {}).get("media"))
        lh = _numero(h.get("latencia_mensaje_ms", {}).get("media"))
        tt = _numero(t.get("throughput_mensajes_por_s"))
        th = _numero(h.get("throughput_mensajes_por_s"))
        # Nunca generar porcentajes si hay errores o la línea base vale cero.
        lat_pct = 100 * (lt / lh - 1) if valido and lh and lt is not None else None
        tp_pct = 100 * (1 - tt / th) if valido and th and tt is not None else None
        resultado.append({
            "usuarios": usuarios, "mensajes": mensajes, "bytes": tamano,
            "repeticion": vuelta.get("repeticion", 1), "archivo": archivo.name,
            "fecha": doc.get("fecha_utc", ""), "tipo": tipo,
            "valido": valido, "tls": t, "http": h,
            "lat_pct": lat_pct, "tp_pct": tp_pct,
        })
    return resultado


def _media(datos):
    vals = [_numero(v) for v in datos]
    validos = [x for x in vals if x is not None]
    return sum(validos) / len(validos) if validos else None


def _resumir(datos: list[dict]) -> list[dict]:
    # Agrupamos por tamaño de carga; se distinguen cargas no equivalentes.
    grupos = defaultdict(list)
    for x in datos:
        grupos[(x["usuarios"], x["mensajes"], x["bytes"])].append(x)
    salida = []
    for (usuarios, mensajes, tamano), filas in sorted(grupos.items()):
        validas = [f for f in filas if f["valido"]]
        salida.append({
            "usuarios": usuarios, "mensajes": mensajes, "bytes": tamano,
            "etiqueta": f"{usuarios} us. / {mensajes} msg / {tamano} B",
            "validas": len(validas), "total": len(filas),
            "tls_tp": _media(f["tls"].get("throughput_mensajes_por_s") for f in validas),
            "http_tp": _media(f["http"].get("throughput_mensajes_por_s") for f in validas),
            "tls_lat": _media(f["tls"].get("latencia_mensaje_ms", {}).get("media") for f in validas),
            "http_lat": _media(f["http"].get("latencia_mensaje_ms", {}).get("media") for f in validas),
            "tls_p95": _media(f["tls"].get("latencia_mensaje_ms", {}).get("p95") for f in validas),
            "http_p95": _media(f["http"].get("latencia_mensaje_ms", {}).get("p95") for f in validas),
            "lat_pct": _media(f["lat_pct"] for f in validas),
            "tp_pct": _media(f["tp_pct"] for f in validas),
            "tls_cpu": _media(f["tls"].get("cpu_pct_medio_1_nucleo",f["tls"].get("cpu_pct_medio")) for f in validas),
            "http_cpu": _media(f["http"].get("cpu_pct_medio_1_nucleo",f["http"].get("cpu_pct_medio")) for f in validas),
            "tls_ram": _media(f["tls"].get("ram_pico_mb") for f in validas),
            "http_ram": _media(f["http"].get("ram_pico_mb") for f in validas),
            "tls_err": sum(int(f["tls"].get("errores", 0)) for f in filas),
            "http_err": sum(int(f["http"].get("errores", 0)) for f in filas),
        })
    return salida


def _svg_barras(grupos, claves, titulo, unidad, colores=(AZUL, VERDE), incluir_cero=True):
    w = 650 if len(grupos) == 1 else max(850, len(grupos) * 174 + 132)
    h = 345
    x0, y0, plot_w, plot_h = 64, 53, w - 98, 216
    vals = [_numero(g.get(k)) for g in grupos for k in claves]
    reales = [v for v in vals if v is not None]
    max_y = max(reales + [0]) if reales else 1
    max_y = max(max_y * 1.17, 1)
    bloques = [f'<svg viewBox="0 0 {w} {h}" role="img" aria-label="{escape(titulo)}" xmlns="http://www.w3.org/2000/svg">']
    for i in range(5):
        yy = y0 + plot_h - i * plot_h / 4
        bloques.append(f'<line x1="{x0}" x2="{x0 + plot_w}" y1="{yy:.1f}" y2="{yy:.1f}" stroke="#dce3ee" stroke-dasharray="3 5"/>')
        bloques.append(f'<text x="{x0 - 9}" y="{yy + 4:.1f}" text-anchor="end" fill="#63718a" font-size="11">{escape(_texto_num(max_y*i/4, 0))}</text>')
    n = max(1, len(grupos))
    paso = plot_w / n
    for i, g in enumerate(grupos):
        centro = x0 + (i + .5) * paso
        for j, clave in enumerate(claves):
            v = _numero(g.get(clave))
            if v is None:
                continue
            bh = (v / max_y) * plot_h
            bw = min(34, (paso - 20) / 2)
            bx = centro + (j - .5) * (bw + 5) - bw/2
            by = y0 + plot_h - bh
            bloques.append(f'<rect x="{bx:.1f}" y="{by:.1f}" width="{bw:.1f}" height="{bh:.1f}" rx="4" fill="{colores[j]}"/>')
            if len(grupos) < 9:
                bloques.append(f'<text x="{bx+bw/2:.1f}" y="{max(20,by-7):.1f}" text-anchor="middle" fill="#283451" font-size="11" font-weight="600">{escape(_texto_num(v, 1))}</text>')
        bloques.append(f'<text x="{centro:.1f}" y="{y0+plot_h+21}" text-anchor="middle" fill="#4a5771" font-size="12">{g["usuarios"]} usuarios</text>')
        bloques.append(f'<text x="{centro:.1f}" y="{y0+plot_h+37}" text-anchor="middle" fill="#8994a7" font-size="10">{g["mensajes"]} × {g["bytes"]} B</text>')
    bloques.append(f'<text x="{x0}" y="{h-11}" fill="#65728b" font-size="11">{escape(unidad)} · Media de repeticiones válidas</text>')
    bloques.append('</svg>')
    return ''.join(bloques)


def _svg_delta(grupos):
    w = 650 if len(grupos) == 1 else max(850, len(grupos)*174+132)
    h, x0, y0, ph = 350, 64, 42, 220
    ww = w-98
    vals = [v for g in grupos for k in ("lat_pct", "tp_pct") if (v := _numero(g.get(k))) is not None]
    amp = max((abs(x) for x in vals), default=1)
    amp = max(amp*1.22, 10)
    cy = y0+ph/2
    bloques = [f'<svg viewBox="0 0 {w} {h}" role="img" aria-label="Porcentajes de overhead" xmlns="http://www.w3.org/2000/svg">',
               f'<line x1="{x0}" x2="{x0+ww}" y1="{cy:.1f}" y2="{cy:.1f}" stroke="#9caac2" stroke-width="2"/>']
    for j in range(-2,3):
        yy = cy - j * (ph/4)
        bloques.append(f'<line x1="{x0}" x2="{x0+ww}" y1="{yy:.1f}" y2="{yy:.1f}" stroke="#e1e6ef" stroke-dasharray="3 5"/>')
        bloques.append(f'<text x="{x0-9}" y="{yy+4:.1f}" text-anchor="end" fill="#65728b" font-size="11">{escape(_texto_num(j * amp/2,0))}%</text>')
    paso=ww/max(len(grupos),1)
    for i,g in enumerate(grupos):
        centro=x0+(i+.5)*paso
        for j, (key, col) in enumerate((("lat_pct",AZUL),("tp_pct",VERDE))):
            v=_numero(g.get(key))
            if v is None:
                continue
            bw=min(34,(paso-20)/2)
            bh=abs(v)/amp*(ph/2)
            bx=centro+(j-.5)*(bw+5)-bw/2
            by=cy-bh if v>=0 else cy
            bloques.append(f'<rect x="{bx:.1f}" y="{by:.1f}" width="{bw:.1f}" height="{bh:.1f}" rx="3" fill="{col}"/>')
            if len(grupos)<9:
                yy=by-6 if v>=0 else by+bh+14
                bloques.append(f'<text x="{bx+bw/2:.1f}" y="{yy:.1f}" text-anchor="middle" fill="#334460" font-size="11" font-weight="600">{escape(_texto_num(v,1))}%</text>')
        bloques.append(f'<text x="{centro:.1f}" y="{y0+ph+23}" text-anchor="middle" fill="#4a5771" font-size="12">{g["usuarios"]} usuarios</text>')
        bloques.append(f'<text x="{centro:.1f}" y="{y0+ph+39}" text-anchor="middle" fill="#8994a7" font-size="10">{g["mensajes"]} × {g["bytes"]} B</text>')
    bloques.append(f'<text x="{x0}" y="{h-8}" fill="#65728b" font-size="11">Valores positivos indican más latencia o menor throughput con TLS.</text></svg>')
    return ''.join(bloques)


def _grafica(titulo: str, descripcion: str, svg: str, leyenda: tuple[str,str], colores=(AZUL,VERDE)):
    return f'''<section class="chart-card"><div class="chart-title"><h2>{escape(titulo)}</h2><p>{escape(descripcion)}</p></div>
      <div class="legend"><span><i style="background:{colores[0]}"></i>{escape(leyenda[0])}</span>
      <span><i style="background:{colores[1]}"></i>{escape(leyenda[1])}</span></div>
      <div class="plot">{svg}</div></section>'''


def generar_html(datos: list[dict], omitidos: list[str] | None = None) -> str:
    omitidos = omitidos or []
    grupos=_resumir(datos)
    buenas=sum(f['valido'] for f in datos)
    malas=len(datos)-buenas
    cargas=len([g for g in grupos if g['validas']])
    maximo=max((g['usuarios'] for g in grupos if g['validas']),default=0)
    ultima = max((str(x.get('fecha','')) for x in datos), default='')
    if len({(g['mensajes'],g['bytes']) for g in grupos})>1:
        distintos = '<div class="alert">Se han realizado ensayos con diferentes tamaños de mensaje o número de mensajes por usuario. Cada grupo se identifica con sus parámetros; las diferencias entre cargas no deben atribuirse exclusivamente al número de usuarios.</div>'
    else:
        distintos = ''
    aviso = '<div class="alert bad">Algunas repeticiones contienen errores. Se muestran sus incidencias, pero se excluyen de las medias y de los porcentajes de sobrecoste. No presentes la batería completa como aprobada.</div>' if malas else ''
    if not buenas:
        aviso += '<div class="alert">Todavía no hay comparativas completas sin errores. Las gráficas de rendimiento se rellenarán cuando ambos escenarios confirmen todos sus mensajes.</div>'
    def tarjeta(label,value,desc):
        return f'<div class="stat"><span>{escape(label)}</span><strong>{escape(str(value))}</strong><small>{escape(desc)}</small></div>'
    tarjetas=''.join([
        tarjeta('Cargas con datos válidos',cargas,'Combinaciones evaluadas'),
        tarjeta('Repeticiones válidas',buenas,'Ambos escenarios sin errores'),
        tarjeta('Repeticiones fallidas',malas,'Excluidas del overhead'),
        tarjeta('Mayor carga medida',f'{maximo} usuarios' if maximo else '—','No equivale a 300 VPN IP'),
    ])
    graficos=''.join([
      _grafica('Throughput','Mayor valor = mayor número de mensajes procesados por segundo.',_svg_barras(grupos,('tls_tp','http_tp'),'Throughput','mensajes/segundo'),('TLS 1.3 + mTLS','HTTP directo')),
      _grafica('Latencia media','Menor valor = respuesta más rápida por mensaje.',_svg_barras(grupos,('tls_lat','http_lat'),'Latencia media','milisegundos'),('TLS 1.3 + mTLS','HTTP directo')),
      _grafica('Latencia p95','Tiempo por debajo del cual termina aproximadamente el 95 % de los mensajes.',_svg_barras(grupos,('tls_p95','http_p95'),'Latencia p95','milisegundos'),('TLS 1.3 + mTLS','HTTP directo')),
      _grafica('Sobrecoste relativo','Solo ensayos completos. Porcentaje positivo: penalización de TLS frente a HTTP.',_svg_delta(grupos),('Aumento de latencia','Pérdida de throughput')),
      _grafica('Errores registrados','Errores de petición; un error puede impedir el envío de mensajes posteriores.',_svg_barras(grupos,('tls_err','http_err'),'Errores','número de errores'),('TLS 1.3 + mTLS','HTTP directo'),(ROJO,'#e5aa6f')),
    ])
    if any(g['tls_cpu'] is not None and g['http_cpu'] is not None for g in grupos):
        graficos += _grafica('Uso medio de CPU',
            'Porcentaje respecto a un núcleo, cuando se pudo identificar el proceso servidor.',
            _svg_barras(grupos,('tls_cpu','http_cpu'),'CPU','% de un núcleo'),
            ('TLS 1.3 + mTLS','HTTP directo'))
    if any(g['tls_ram'] is not None and g['http_ram'] is not None for g in grupos):
        graficos += _grafica('RAM máxima observada',
            'Memoria residente RSS durante el ensayo; requiere identificar el proceso servidor.',
            _svg_barras(grupos,('tls_ram','http_ram'),'RAM','MB'),
            ('TLS 1.3 + mTLS','HTTP directo'))
    filas=[]
    for g in grupos:
        estado = f'<span class="pill ok">{g["validas"]}/{g["total"]} válidas</span>' if g['validas']==g['total'] else f'<span class="pill warn">{g["validas"]}/{g["total"]} válidas</span>'
        filas.append('<tr>'+''.join(f'<td>{valor}</td>' for valor in [
            f'{g["usuarios"]} usuarios', f'{g["mensajes"]} × {g["bytes"]} B',
            estado, _texto_num(g['tls_tp']), _texto_num(g['http_tp']),
            _texto_num(g['tls_lat']),_texto_num(g['http_lat']),
            _texto_num(g['lat_pct'])+'%' if g['lat_pct'] is not None else '—',
            _texto_num(g['tp_pct'])+'%' if g['tp_pct'] is not None else '—',
        ])+'</tr>')
    si = []
    for f in sorted(datos,key=lambda x:(x['usuarios'],x['archivo'],int(x['repeticion']))):
        si.append('<tr>'+''.join(f'<td>{escape(str(v))}</td>' for v in [
            f['usuarios'],f['repeticion'],f['archivo'],
            'VÁLIDA' if f['valido'] else 'INCOMPLETA',
            f['tls'].get('mensajes_confirmados','—'),f['tls'].get('errores','—'),
            f['http'].get('mensajes_confirmados','—'),f['http'].get('errores','—'),
        ])+'</tr>')
    comentarios = '<p class="dim">Se omitieron archivos no compatibles o ilegibles: '+escape(', '.join(omitidos[:20]))+'</p>' if omitidos else ''
    return f'''<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RS3 · Rendimiento BYODSEC</title>
<style>
:root{{--bg:#f4f6fc;--ink:#1c2b46;--muted:#617089;--line:#dce4f0;--panel:#fff;--blue:{AZUL};--green:{VERDE}}}
*{{box-sizing:border-box}}html{{scroll-behavior:smooth}}body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,'Segoe UI',sans-serif}}
header{{background:linear-gradient(122deg,#12213e 0%,#203b70 73%,#1e577b 100%);color:white;padding:48px max(22px,calc((100vw - 1260px)/2));}}
header .eyebrow{{letter-spacing:.18em;text-transform:uppercase;color:#8fd6da;font-size:12px;font-weight:750}}h1{{font-size:clamp(28px,4vw,44px);margin:8px 0 9px;letter-spacing:-.035em}}header p{{color:#d0e0f5;max-width:690px;margin:0}}
nav{{display:flex;gap:12px;flex-wrap:wrap;margin-top:26px}}nav a{{border:1px solid #6a83af;border-radius:999px;padding:7px 14px;color:white;text-decoration:none;font-size:13px}}nav a:hover{{background:#ffffff22}}
main{{max-width:1300px;margin:auto;padding:30px 22px 50px}}.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:20px}}.stat{{background:var(--panel);border:1px solid var(--line);padding:20px;border-radius:16px;display:flex;flex-direction:column;gap:3px;box-shadow:0 4px 15px #16223f08}}
.stat span{{font-size:13px;color:var(--muted)}}.stat strong{{font-size:29px;letter-spacing:-.03em}}.stat small{{font-size:12px;color:var(--muted)}}
.alert{{background:#fff7e5;border-left:4px solid #d99a25;padding:13px 16px;border-radius:8px;margin:14px 0;color:#634b24}}.alert.bad{{background:#fff0ed;border-color:#e27b56;color:#853e30}}
.section-label{{font-size:12px;color:#61769b;font-weight:800;text-transform:uppercase;letter-spacing:.16em;margin:33px 0 12px}}.charts{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px}}
.chart-card,.table-card,.info{{background:var(--panel);border:1px solid var(--line);border-radius:17px;box-shadow:0 4px 18px #172a4707;padding:23px;min-width:0}}
.chart-title h2{{font-size:19px;margin:0 0 4px;letter-spacing:-.01em}}.chart-title p{{color:var(--muted);font-size:12px;margin:0 0 14px;min-height:34px}}
.legend{{display:flex;gap:18px;flex-wrap:wrap;font-size:12px;color:#586781;margin-bottom:6px}}.legend span{{display:flex;align-items:center;gap:7px}}.legend i{{width:11px;height:11px;display:block;border-radius:3px}}.plot{{overflow:auto}}.plot svg{{display:block;width:100%;min-width:450px;height:auto}}
table{{border-collapse:collapse;min-width:830px;width:100%;font-size:13px}}th,td{{text-align:left;padding:12px 11px;border-bottom:1px solid #e7ecf4;white-space:nowrap}}th{{background:#f7f9fd;color:#52637c;font-size:12px}}tr:last-child td{{border-bottom:0}}.table-wrapper{{overflow:auto}}.pill{{display:inline-block;padding:4px 9px;border-radius:99px;font-size:12px;font-weight:700}}.pill.ok{{background:#e7f7f3;color:#087666}}.pill.warn{{background:#fff0e7;color:#a55429}}.dim,.info p{{color:var(--muted);font-size:13px}}.info ul{{color:var(--muted);padding-left:21px;font-size:13px}}footer{{color:#71809c;font-size:12px;padding-top:25px}}
@media(max-width:850px){{.stats{{grid-template-columns:repeat(2,1fr)}}.charts{{grid-template-columns:1fr}}}}@media(max-width:490px){{.stats{{grid-template-columns:1fr 1fr}}.stat{{padding:13px}}.stat strong{{font-size:22px}}}}
@media print{{nav{{display:none}}body{{background:white}}.chart-card{{break-inside:avoid}}}}
</style></head><body>
<header><div class="eyebrow">BYODSEC · PAI-2 · Objetivo 3 / RS3</div><h1>Rendimiento del canal seguro · 300 usuarios</h1><p>Comparación experimental de HTTPS/TLS 1.3 con autenticación mutua frente a HTTP sin cifrar en localhost. Datos extraídos automáticamente de los informes JSON de las pruebas.</p><nav><a href="#graficas">Gráficas</a><a href="#resumen">Resumen numérico</a><a href="#trazabilidad">Trazabilidad</a><a href="#metodologia">Metodología</a></nav></header>
<main><div class="stats">{tarjetas}</div>{aviso}{distintos}
<div class="section-label" id="graficas">Visualización de resultados</div><div class="charts">{graficos}</div>
<div class="section-label" id="resumen">Tabla comparativa</div><div class="table-card"><div class="table-wrapper"><table><thead><tr><th>Carga</th><th>Mensajes / tamaño</th><th>Repeticiones</th><th>TLS msg/s</th><th>HTTP msg/s</th><th>TLS ms</th><th>HTTP ms</th><th>Δ latencia</th><th>Pérdida throughput</th></tr></thead><tbody>{''.join(filas) if filas else '<tr><td colspan="9">Todavía no hay resultados compatibles.</td></tr>'}</tbody></table></div></div>
<div class="section-label" id="trazabilidad">Repeticiones y errores</div><div class="table-card"><div class="table-wrapper"><table><thead><tr><th>Usuarios</th><th>Repetición</th><th>Archivo JSON</th><th>Estado</th><th>TLS confirmados</th><th>TLS errores</th><th>HTTP confirmados</th><th>HTTP errores</th></tr></thead><tbody>{''.join(si) if si else '<tr><td colspan="8">Sin datos.</td></tr>'}</tbody></table></div>{comentarios}</div>
<div class="section-label" id="metodologia">Cómo interpretar este informe</div><section class="info"><p><strong>Indicadores.</strong> El throughput representa mensajes confirmados por segundo y la latencia representa el tiempo medio de una petición. Las gráficas muestran medias de repeticiones completas, mientras que la tabla de trazabilidad conserva los fallos.</p>
<ul><li><strong>Sobrecoste de latencia:</strong> (latencia TLS / latencia HTTP − 1) × 100.</li><li><strong>Pérdida de throughput:</strong> (1 − throughput TLS / throughput HTTP) × 100.</li><li><strong>Comparabilidad:</strong> solo se calculan porcentajes cuando ambos escenarios completaron todos los mensajes y no hubo errores. Los resultados de cada repetición se emparejan antes de calcular el porcentaje.</li><li><strong>Alcance:</strong> mide tráfico HTTPS con mTLS y validación del token, frente a HTTP directo sin autenticación, en WSL2 local; NO mide un túnel VPN IP ni permite atribuir toda la diferencia exclusivamente al coste criptográfico.</li><li><strong>CPU/RAM:</strong> se muestran cuando están disponibles; las medidas ausentes no se sustituyen por ceros.</li><li><strong>Concurrencia:</strong> las mediciones de esta comparativa no sustituyen a la prueba independiente de 300 sesiones simultáneas durante 30 segundos.</li></ul></section>
<footer>Informe autónomo generado por tools/informe_rs3.py · Última medición encontrada: {escape(ultima or 'sin fecha')} · No contiene credenciales ni mensajes transmitidos.</footer>
</main></body></html>'''


def generar_informe(directorio: Path | str, salida: Path | str, adicionales=(), usuarios: int | None = 300) -> dict:
    directorio=Path(directorio)
    salida=Path(salida)
    archivos={p.resolve() for p in directorio.glob('comparativa*.json') if p.is_file()}
    archivos.update(Path(p).resolve() for p in adicionales if Path(p).is_file())
    datos=[]
    omitidos=[]
    for archivo in sorted(archivos):
        try:
            doc=json.loads(archivo.read_text(encoding='utf-8'))
            filas=_extraer_corridas(doc,archivo)
            if not filas:
                omitidos.append(archivo.name)
            datos.extend(f for f in filas if usuarios is None or f["usuarios"] == usuarios)
        except (OSError, ValueError, TypeError, KeyError):
            omitidos.append(archivo.name)
    salida.parent.mkdir(parents=True,exist_ok=True)
    salida.write_text(generar_html(datos,omitidos),encoding='utf-8')
    return {'archivo':str(salida),'archivos_leidos':len(archivos),'repeticiones':len(datos),
            'validas':sum(x['valido'] for x in datos),'omitidos':omitidos, 'usuarios_filtro': usuarios}


def main():
    p=argparse.ArgumentParser(description='Dashboard HTML local para RS3 (solo librería estándar).')
    p.add_argument('--directorio',type=Path,default=RAIZ/'bench/resultados')
    p.add_argument('--salida',type=Path,default=RAIZ/'bench/resultados/informe_rs3.html')
    p.add_argument('--usuarios', type=int, default=300,
                   help='Solo incluir cargas de este número de usuarios (por defecto: 300; 0 para todas).')
    a=p.parse_args()
    if a.usuarios < 0:
        p.error('--usuarios debe ser 0 o un entero positivo')
    res=generar_informe(a.directorio,a.salida, usuarios=a.usuarios or None)
    print(f"[RS3] Informe HTML: {res['archivo']}")
    print(f"[RS3] Carga mostrada: {res['usuarios_filtro'] or 'todas'} usuarios.")
    print(f"[RS3] {res['repeticiones']} repeticiones encontradas; {res['validas']} válidas.")
    return 0


if __name__=='__main__':
    raise SystemExit(main())
