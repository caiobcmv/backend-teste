# Por padrão: field1 = temperatura, field2 = umidade (configurável em TS_FIELD_* no .env).
import requests
from src import config

BASE_URL = "https://api.thingspeak.com"


def buscar_ultima_leitura():
    url = f"{BASE_URL}/channels/{config.THINGSPEAK_CHANNEL_ID}/feeds/last.json"
    params = {}
    if config.THINGSPEAK_READ_API_KEY:
        params["api_key"] = config.THINGSPEAK_READ_API_KEY

    resp = requests.get(url, params=params, timeout=10)
    resp.raise_for_status()
    dado = resp.json()

    # Canal vazio retorna {} ou campos vazios
    if not dado or dado.get("entry_id") is None:
        return None

    return _montar_leitura(dado)


def buscar_leituras(quantidade=100):
    url = f"{BASE_URL}/channels/{config.THINGSPEAK_CHANNEL_ID}/feeds.json"
    params = {"results": quantidade}
    if config.THINGSPEAK_READ_API_KEY:
        params["api_key"] = config.THINGSPEAK_READ_API_KEY

    resp = requests.get(url, params=params, timeout=10)
    resp.raise_for_status()
    dado = resp.json()

    leituras = []
    for feed in dado.get("feeds", []):
        if feed.get("entry_id") is None:
            continue
        leituras.append(_montar_leitura(feed))
    return leituras


def _campo(feed, numero):
    """Valor do field N do feed (None se o field não foi mapeado)."""
    return feed.get(f"field{numero}") if numero else None


def _montar_leitura(feed):
    """Converte um feed do ThingSpeak no dicionário usado pelo resto do sistema.
    Os números dos fields vêm do .env (TS_FIELD_*). Solo só entra se estiver mapeado."""
    leitura = {
        "entry_id": feed["entry_id"],
        "created_at": feed["created_at"],
        "temperatura": _float_seguro(_campo(feed, config.TS_FIELD_TEMPERATURA)),
        "umidade": _float_seguro(_campo(feed, config.TS_FIELD_UMIDADE)),
        # valores originais usados no log de leituras rejeitadas
        "temperatura_bruta": _campo(feed, config.TS_FIELD_TEMPERATURA),
        "umidade_bruta": _campo(feed, config.TS_FIELD_UMIDADE),
    }
    if config.TS_FIELD_UMIDADE_SOLO:
        leitura["umidade_solo"] = _float_seguro(_campo(feed, config.TS_FIELD_UMIDADE_SOLO))
        leitura["umidade_solo_bruta"] = _campo(feed, config.TS_FIELD_UMIDADE_SOLO)
    if config.TS_FIELD_TEMPERATURA_SOLO:
        leitura["temperatura_solo"] = _float_seguro(_campo(feed, config.TS_FIELD_TEMPERATURA_SOLO))
        leitura["temperatura_solo_bruta"] = _campo(feed, config.TS_FIELD_TEMPERATURA_SOLO)
    return leitura


def _float_seguro(valor):
    if valor is None:
        return None
    try:
        return float(valor)
    except (TypeError, ValueError):
        return None
