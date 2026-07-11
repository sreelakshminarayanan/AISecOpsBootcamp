from __future__ import annotations

from typing import Any

import requests

from detection_lab.config import service_auth


class ServiceError(RuntimeError):
    pass


def request_json(method: str, url: str, *, expected: tuple[int, ...] = (200,), **kwargs: Any) -> Any:
    if "auth" not in kwargs:
        auth = service_auth(url)
        if auth:
            kwargs["auth"] = auth
    try:
        response = requests.request(method, url, timeout=kwargs.pop("timeout", 60), **kwargs)
    except requests.RequestException as exc:
        raise ServiceError(f"Request failed for {url}: {exc}") from exc
    if response.status_code not in expected:
        body = response.text[:1000]
        raise ServiceError(f"{method} {url} returned {response.status_code}: {body}")
    if not response.content:
        return {}
    try:
        return response.json()
    except ValueError:
        return {"text": response.text}
