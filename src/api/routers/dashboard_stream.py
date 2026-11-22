import asyncio
import json
import random
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse

from src.api.deps import get_conn

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

INTERVALO_S = 5                        # frequência de checagem/envio
HEARTBEAT_S = 15                       # comentário SSE para manter a conexão viva
LEITURA_VELHA = timedelta(minutes=10)  # acima disso, considera o sensor offline

# Base da simulação (fallback)
TEMP_BASE = 27.2
UMID_BASE = 61.0


def buscar_ultima_leitura():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT temperatura, umidade, data_hora
                FROM leitura_climatica
                ORDER BY data_hora DESC
                LIMIT 1
                """
            )
            row = cur.fetchone()
    if not row:
        return None
    return {
        "temperatura": float(row[0]),
        "umidade": float(row[1]),
        "data_hora": row[2],
    }


def leitura_simulada():
    return {
        "temperatura": round(TEMP_BASE + random.uniform(-0.3, 0.3), 1),
        "umidade": round(UMID_BASE + random.uniform(-0.8, 0.8), 1),
    }


def montar_payload():
    """Tenta dado real; se não houver ou estiver velho, simula."""
    agora = datetime.now(timezone.utc)
    real = None
    try:
        real = buscar_ultima_leitura()
    except Exception:
        real = None  # banco indisponível: não derruba o stream

    if real:
        dh = real["data_hora"]
        if dh.tzinfo is None:
            dh = dh.replace(tzinfo=timezone.utc)
        if agora - dh <= LEITURA_VELHA:
            return {
                "temperatura": real["temperatura"],
                "umidade": real["umidade"],
                "origem": "real",
                "timestamp": dh.isoformat(),
                "sensor": "DHT11 ESP32-C3",
            }

    sim = leitura_simulada()
    return {
        **sim,
        "origem": "simulado",
        "timestamp": agora.isoformat(),
        "sensor": "DHT11 ESP32-C3 (simulado)",
    }


async def gerador_leituras(request: Request):
    """Fluxo SSE contínuo. Encerra quando o cliente desconecta."""
    loop = asyncio.get_event_loop()
    ultima_msg = loop.time()
    ultimo_envio = None

    while True:
        if await request.is_disconnected():
            break

        payload = await run_in_threadpool(montar_payload)

        # Real só é reenviado se mudou (ThingSpeak atualiza a cada ~15 s).
        # Simulado sempre é enviado, para o gráfico "respirar".
        chave = (payload["origem"], payload["timestamp"])
        if payload["origem"] == "simulado" or chave != ultimo_envio:
            yield f"data: {json.dumps(payload)}\n\n"
            ultimo_envio = chave
            ultima_msg = loop.time()
        elif loop.time() - ultima_msg >= HEARTBEAT_S:
            yield ": keep-alive\n\n"  # comentário SSE, o front ignora
            ultima_msg = loop.time()

        await asyncio.sleep(INTERVALO_S)


@router.get("/stream")
async def stream_telemetria_ao_vivo(request: Request):
    """Endpoint SSE (Server-Sent Events) para o dashboard em tempo real."""
    return StreamingResponse(
        gerador_leituras(request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  
        },
    )