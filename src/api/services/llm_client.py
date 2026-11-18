import json
import os

import httpx

TIMEOUT = 45.0


class LLMError(Exception):
    pass


def _limpar_json(texto: str) -> dict:
    texto = texto.strip()
    if texto.startswith("```"):
        texto = texto.strip("`")
        if texto.lower().startswith("json"):
            texto = texto[4:]
    try:
        return json.loads(texto)
    except json.JSONDecodeError as e:
        raise LLMError(f"Resposta da IA não é JSON válido: {e}") from e


def _gemini(system: str, user: str, model: str) -> str:
    key = os.environ["GEMINI_API_KEY"]
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    body = {
        "systemInstruction": {"parts": [{"text": system}]},
        "contents": [{"role": "user", "parts": [{"text": user}]}],
        "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json"},
    }
    r = httpx.post(url, headers={"x-goog-api-key": key}, json=body, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()["candidates"][0]["content"]["parts"][0]["text"]


def _groq(system: str, user: str, model: str) -> str:
    key = os.environ["GROQ_API_KEY"]
    body = {
        "model": model,
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    r = httpx.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {key}"},
        json=body,
        timeout=TIMEOUT,
    )
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]


def _ollama(system: str, user: str, model: str) -> str:
    base = os.environ.get("OLLAMA_URL", "http://localhost:11434")
    body = {
        "model": model,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.2},
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    r = httpx.post(f"{base}/api/chat", json=body, timeout=120.0)
    r.raise_for_status()
    return r.json()["message"]["content"]


_PROVEDORES = {"gemini": _gemini, "groq": _groq, "ollama": _ollama}


def gerar_json(system: str, user: str) -> tuple[dict, str]:
    """Chama o provedor configurado e devolve (dict_json, 'provedor:modelo').

    Levanta LLMError em qualquer falha (rede, cota, JSON inválido), para o
    chamador cair no parecer de contingência por template.
    """
    provedor = os.environ.get("LLM_PROVIDER", "gemini").lower()
    if provedor not in _PROVEDORES:
        raise LLMError(f"LLM_PROVIDER inválido: {provedor}")
    model = os.environ.get("LLM_MODEL") or ("gemini-2.5-flash" if provedor == "gemini" else None)
    if not model:
        raise LLMError("Defina LLM_MODEL no .env")
    try:
        bruto = _PROVEDORES[provedor](system, user, model)
    except (httpx.HTTPError, KeyError, IndexError) as e:
        raise LLMError(f"Falha ao chamar {provedor}: {e}") from e
    return _limpar_json(bruto), f"{provedor}:{model}"