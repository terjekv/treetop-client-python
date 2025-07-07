from __future__ import annotations

import contextlib
from typing import Any, Final

import httpx

from treetop_client.models import (
    CheckResponse,
    CheckResponseBrief,
    Endpoint,
    Request,
    as_api,
)

_DEFAULT_LIMITS: Final = httpx.Limits(
    max_connections=100,
    max_keepalive_connections=20,
)


class _Singleton(type):
    _instance: TreeTopClient | None = None

    def __call__(cls, *args, **kwargs):  # type: ignore[override]
        """Ensure that only one instance of TreeTopClient exists."""
        if cls._instance is None:
            cls._instance = super().__call__(*args, **kwargs)
        return cls._instance


class TreeTopClient(metaclass=_Singleton):
    def __init__(
        self,
        base_url: str = "http://localhost:9999",
        *,
        limits: httpx.Limits | None = None,
        timeout: float | httpx.Timeout = 5.0,
        verify: bool | str = True,
    ):
        self._sync_client = httpx.Client(
            base_url=base_url,
            limits=limits or _DEFAULT_LIMITS,
            timeout=timeout,
            verify=verify,
        )
        self._async_client = httpx.AsyncClient(
            base_url=base_url,
            limits=limits or _DEFAULT_LIMITS,
            timeout=timeout,
            verify=verify,
        )

    def check(self, request: Request | dict[str, Any]) -> CheckResponseBrief:
        """Check the given request. Synchronous version.

        Args:
            request: The request to check, either as a Request object or a dictionary.
        Returns:
            A CheckResponseBrief containing the result of the check.
        Raises:
            httpx.HTTPStatusError: If the request fails with a non-2xx status code
        """
        resp = self._sync_client.post(Endpoint.CHECK.value, json=as_api(request))
        resp.raise_for_status()
        return CheckResponseBrief.from_api(resp.json())

    def check_detailed(self, request: Request | dict[str, Any]) -> CheckResponse:
        """Check the given request with detailed output. Synchronous version.

        If the request is "Allow", the detailed check provides the policy that was matched,
        both in cedar format ("literal") and as json "json".

        Args:
            request: The request to check, either as a Request object or a dictionary.
        Returns:
            A CheckResponse containing the detailed result of the check.
        Raises:
            httpx.HTTPStatusError: If the request fails with a non-2xx status code
        """
        resp = self._sync_client.post(
            Endpoint.CHECK_DETAILED.value, json=as_api(request)
        )
        resp.raise_for_status()
        return CheckResponse.from_api(resp.json())

    async def acheck(self, request: Request | dict[str, Any]) -> CheckResponseBrief:
        """Check the given request. Asynchronous version.

        Args:
            request: The request to check, either as a Request object or a dictionary.
        Returns:
            A CheckResponseBrief containing the result of the check.
        Raises:
            httpx.HTTPStatusError: If the request fails with a non-2xx status code
        """
        resp = await self._async_client.post(Endpoint.CHECK.value, json=as_api(request))
        resp.raise_for_status()
        return CheckResponseBrief.from_api(resp.json())

    async def acheck_detailed(self, request: Request | dict[str, Any]) -> CheckResponse:
        """Check the given request with detailed output. Asynchronous version.

        If the request is "Allow", the detailed check provides the policy that was matched,
        both in cedar format ("literal") and as json "json".
        Args:
            request: The request to check, either as a Request object or a dictionary.
        Returns:
            A CheckResponse containing the detailed result of the check.
        Raises:
            httpx.HTTPStatusError: If the request fails with a non-2xx status code
        """
        resp = await self._async_client.post(
            Endpoint.CHECK_DETAILED.value, json=as_api(request)
        )
        resp.raise_for_status()
        return CheckResponse.from_api(resp.json())

    def close(self):
        """Close the synchronous client connection."""
        with contextlib.suppress(Exception):
            self._sync_client.close()
        TreeTopClient._instance = None  # type: ignore

    async def aclose(self):
        """Close the asynchronous client connection."""
        await self._async_client.aclose()
        self._sync_client.close()
        TreeTopClient._instance = None  # type: ignore


# For typing convenience
RequestLike = Request | dict[str, Any]
