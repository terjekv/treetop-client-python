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

    def _build_headers(self, correlation_id: str | None) -> dict[str, str] | None:
        """Build headers for the request, including a correlation ID if provided."""
        if not correlation_id:
            return None
        return {"X-Correlation-ID": correlation_id}

    def _sync_post(
        self,
        url: str,
        json_body: dict[str, Any],
        correlation_id: str | None = None,
    ) -> httpx.Response:
        """Synchronous POST request to the given URL with JSON body and optional correlation ID."""
        return self._sync_client.post(
            url,
            json=json_body,
            headers=self._build_headers(correlation_id),
        )

    async def _async_post(
        self,
        url: str,
        json_body: dict[str, Any],
        correlation_id: str | None = None,
    ) -> httpx.Response:
        """Asynchronous POST request to the given URL with JSON body and optional correlation ID."""
        return await self._async_client.post(
            url,
            json=json_body,
            headers=self._build_headers(correlation_id),
        )

    def check(
        self, request: Request | dict[str, Any], correlation_id: str | None = None
    ) -> CheckResponseBrief:
        """Check the given request. Synchronous version.

        Args:
            request: The request to check, either as a Request object or a dictionary.
            correlation_id: Optional correlation ID for tracing the request.
        Returns:
            A CheckResponseBrief containing the result of the check.
        Raises:
            httpx.HTTPStatusError: If the request fails with a non-2xx status code
        """
        resp = self._sync_post(
            Endpoint.CHECK.value,
            json_body=as_api(request),
            correlation_id=correlation_id,
        )
        resp.raise_for_status()
        return CheckResponseBrief.from_api(resp.json())

    def check_detailed(
        self, request: Request | dict[str, Any], correlation_id: str | None = None
    ) -> CheckResponse:
        """Check the given request with detailed output. Synchronous version.

        If the request is "Allow", the detailed check provides the policy that was matched,
        both in cedar format ("literal") and as json "json".

        Args:
            request: The request to check, either as a Request object or a dictionary.
            correlation_id: Optional correlation ID for tracing the request.
        Returns:
            A CheckResponse containing the detailed result of the check.
        Raises:
            httpx.HTTPStatusError: If the request fails with a non-2xx status code
        """
        resp = self._sync_post(
            Endpoint.CHECK_DETAILED.value,
            json_body=as_api(request),
            correlation_id=correlation_id,
        )
        resp.raise_for_status()
        return CheckResponse.from_api(resp.json())

    async def acheck(
        self, request: Request | dict[str, Any], correlation_id: str | None = None
    ) -> CheckResponseBrief:
        """Check the given request. Asynchronous version.

        Args:
            request: The request to check, either as a Request object or a dictionary.
            correlation_id: Optional correlation ID for tracing the request.
        Returns:
            A CheckResponseBrief containing the result of the check.
        Raises:
            httpx.HTTPStatusError: If the request fails with a non-2xx status code
        """
        resp = await self._async_post(
            Endpoint.CHECK.value,
            json_body=as_api(request),
            correlation_id=correlation_id,
        )
        resp.raise_for_status()
        return CheckResponseBrief.from_api(resp.json())

    async def acheck_detailed(
        self, request: Request | dict[str, Any], correlation_id: str | None = None
    ) -> CheckResponse:
        """Check the given request with detailed output. Asynchronous version.

        If the request is "Allow", the detailed check provides the policy that was matched,
        both in cedar format ("literal") and as json "json".
        Args:
            request: The request to check, either as a Request object or a dictionary.
            correlation_id: Optional correlation ID for tracing the request.
        Returns:
            A CheckResponse containing the detailed result of the check.
        Raises:
            httpx.HTTPStatusError: If the request fails with a non-2xx status code
        """
        resp = await self._async_post(
            Endpoint.CHECK_DETAILED.value,
            json_body=as_api(request),
            correlation_id=correlation_id,
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
