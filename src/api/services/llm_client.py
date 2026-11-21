"""Cliente único de LLM (Gemini, Groq ou Ollama), só com `requests` (já está no requirements.txt)."""
import json
import os

import requests

TIMEOUT = 30.0


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
    key = os.environ.get("GEMINI_API_KEY")
    if not key:
        raise LLMError("GEMINI_API_KEY não encontrada no ambiente.")
    body = {
        "systemInstruction": {"parts": [{"text": system}]},
        "contents": [{"role": "user", "parts": [{"text": user}]}],
        "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json"},
    }
    # a chave vai no header (não na URL), para não aparecer em mensagens de erro/logs
    r = requests.post(
        f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        headers={"x-goog-api-key": key},
        json=body,
        timeout=TIMEOUT,
    )
    r.raise_for_status()
    try:
        return r.json()["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError, TypeError) as e:
        raise LLMError("Resposta inesperada do Gemini (sem texto).") from e


def _groq(system: str, user: str, model: str) -> str:
    key = os.environ.get("GROQ_API_KEY")
    if not key:
        raise LLMError("GROQ_API_KEY não encontrada no ambiente.")
    body = {
        "model": model,
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    r = requests.post(
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
    r = requests.post(f"{base}/api/chat", json=body, timeout=120.0)
    r.raise_for_status()
    return r.json()["message"]["content"]


_PROVEDORES = {"gemini": _gemini, "groq": _groq, "ollama": _ollama}


def gerar_json(system: str, user: str) -> tuple[dict, str]:
    """Chama o provedor configurado e devolve (dict_json, 'provedor:modelo').

    Levanta LLMError em qualquer falha (rede, cota, JSON inválido).
    """
    provedor = os.environ.get("LLM_PROVIDER", "gemini").lower()
    if provedor not in _PROVEDORES:
        raise LLMError(f"LLM_PROVIDER inválido: {provedor}")

    model = os.environ.get("LLM_MODEL") or ("gemini-2.5-flash" if provedor == "gemini" else None)
    if not model:
        raise LLMError("Defina LLM_MODEL no .env")

    try:
        bruto = _PROVEDORES[provedor](system, user, model)
    except LLMError:
        raise
    except Exception as e:
        raise LLMError(f"Falha ao chamar {provedor}: {e}") from e

    return _limpar_json(bruto), f"{provedor}:{model}"
