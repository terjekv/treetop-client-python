from __future__ import annotations

import contextlib
from collections.abc import Sequence
from typing import Any, Final

import httpx

from treetop_client.models import (AuthorizedResponseBrief,
                                   AuthorizedResponseDetailed,
                                   AuthorizeResponseBrief,
                                   AuthorizeResponseDetailed, Decision,
                                   Endpoint, Request, as_api)

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
        params: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Synchronous POST request to the given URL with JSON body and optional correlation ID."""
        return self._sync_client.post(
            url,
            json=json_body,
            headers=self._build_headers(correlation_id),
            params=params,
        )

    async def _async_post(
        self,
        url: str,
        json_body: dict[str, Any],
        correlation_id: str | None = None,
        params: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Asynchronous POST request to the given URL with JSON body and optional correlation ID."""
        return await self._async_client.post(
            url,
            json=json_body,
            headers=self._build_headers(correlation_id),
            params=params,
        )

    def authorize(
        self,
        requests: Request | dict[str, Any] | Sequence[Request | dict[str, Any]],
        correlation_id: str | None = None,
    ) -> AuthorizeResponseBrief:
        """Authorize one or more requests (brief detail level). Synchronous version.

        Args:
            requests: A single request or list of requests. Can be Request objects or dictionaries.
            correlation_id: Optional correlation ID for tracing the request.
        Returns:
            An AuthorizeResponseBrief containing the batch results.
        Raises:
            httpx.HTTPStatusError: If the request fails with a non-2xx status code
        """
        request_list: list[dict[str, Any]] = []
        if isinstance(requests, (Request, dict)):
            request_list = [as_api(requests)]
        else:
            request_list = [as_api(req) for req in requests]
        resp = self._sync_post(
            Endpoint.AUTHORIZE.value,
            json_body={"requests": request_list},
            correlation_id=correlation_id,
        )
        resp.raise_for_status()
        return AuthorizeResponseBrief.from_api(resp.json())

    def authorize_detailed(
        self,
        requests: Request | dict[str, Any] | Sequence[Request | dict[str, Any]],
        correlation_id: str | None = None,
    ) -> AuthorizeResponseDetailed:
        """Authorize one or more requests (detailed with policy info). Synchronous version.

        Args:
            requests: A single request or list of requests. Can be Request objects or dictionaries.
            correlation_id: Optional correlation ID for tracing the request.
        Returns:
            An AuthorizeResponseDetailed containing the batch results with policy info.
        Raises:
            httpx.HTTPStatusError: If the request fails with a non-2xx status code
        """
        request_list: list[dict[str, Any]] = []
        if isinstance(requests, (Request, dict)):
            request_list = [as_api(requests)]
        else:
            request_list = [as_api(req) for req in requests]
        resp = self._sync_post(
            Endpoint.AUTHORIZE.value,
            json_body={"requests": request_list},
            correlation_id=correlation_id,
            params={"detail": "full"},
        )
        resp.raise_for_status()
        return AuthorizeResponseDetailed.from_api(resp.json())

    async def aauthorize(
        self,
        requests: Request | dict[str, Any] | Sequence[Request | dict[str, Any]],
        correlation_id: str | None = None,
    ) -> AuthorizeResponseBrief:
        """Authorize one or more requests (brief detail level). Asynchronous version.

        Args:
            requests: A single request or list of requests. Can be Request objects or dictionaries.
            correlation_id: Optional correlation ID for tracing the request.
        Returns:
            An AuthorizeResponseBrief containing the batch results.
        Raises:
            httpx.HTTPStatusError: If the request fails with a non-2xx status code
        """
        request_list: list[dict[str, Any]] = []
        if isinstance(requests, (Request, dict)):
            request_list = [as_api(requests)]
        else:
            request_list = [as_api(req) for req in requests]
        resp = await self._async_post(
            Endpoint.AUTHORIZE.value,
            json_body={"requests": request_list},
            correlation_id=correlation_id,
        )
        resp.raise_for_status()
        return AuthorizeResponseBrief.from_api(resp.json())

    async def aauthorize_detailed(
        self,
        requests: Request | dict[str, Any] | Sequence[Request | dict[str, Any]],
        correlation_id: str | None = None,
    ) -> AuthorizeResponseDetailed:
        """Authorize one or more requests (detailed with policy info). Asynchronous version.

        Args:
            requests: A single request or list of requests. Can be Request objects or dictionaries.
            correlation_id: Optional correlation ID for tracing the request.
        Returns:
            An AuthorizeResponseDetailed containing the batch results with policy info.
        Raises:
            httpx.HTTPStatusError: If the request fails with a non-2xx status code
        """
        request_list: list[dict[str, Any]] = []
        if isinstance(requests, (Request, dict)):
            request_list = [as_api(requests)]
        else:
            request_list = [as_api(req) for req in requests]
        resp = await self._async_post(
            Endpoint.AUTHORIZE.value,
            json_body={"requests": request_list},
            correlation_id=correlation_id,
            params={"detail": "full"},
        )
        resp.raise_for_status()
        return AuthorizeResponseDetailed.from_api(resp.json())

    # Compatibility methods for single-request API (wraps batch API)
    def check(
        self, request: Request | dict[str, Any], correlation_id: str | None = None
    ) -> AuthorizedResponseBrief:
        """Check the given request. Synchronous version (compatibility wrapper).

        This method provides backward compatibility with the old single-request API.
        It wraps the new batch authorize endpoint.

        Args:
            request: The request to check, either as a Request object or a dictionary.
            correlation_id: Optional correlation ID for tracing the request.
        Returns:
            An AuthorizedResponseBrief containing the result of the check.
        Raises:
            httpx.HTTPStatusError: If the request fails with a non-2xx status code
        """
        response = self.authorize(request, correlation_id=correlation_id)
        if not response.results:
            raise ValueError("No results returned from authorize endpoint")
        result = response.results[0]
        if result.status == "failed":
            raise RuntimeError(f"Authorization failed: {result.error}")
        return result.result or AuthorizedResponseBrief(Decision.DENY)

    def check_detailed(
        self, request: Request | dict[str, Any], correlation_id: str | None = None
    ) -> AuthorizedResponseDetailed:
        """Check the given request with detailed output. Synchronous version (compatibility wrapper).

        This method provides backward compatibility with the old single-request API.
        It wraps the new batch authorize_detailed endpoint.

        Args:
            request: The request to check, either as a Request object or a dictionary.
            correlation_id: Optional correlation ID for tracing the request.
        Returns:
            An AuthorizedResponseDetailed containing the detailed result of the check.
        Raises:
            httpx.HTTPStatusError: If the request fails with a non-2xx status code
        """
        response = self.authorize_detailed(request, correlation_id=correlation_id)
        if not response.results:
            raise ValueError("No results returned from authorize endpoint")
        result = response.results[0]
        if result.status == "failed":
            raise RuntimeError(f"Authorization failed: {result.error}")
        return result.result or AuthorizedResponseDetailed(Decision.DENY, None, None)

    async def acheck(
        self, request: Request | dict[str, Any], correlation_id: str | None = None
    ) -> AuthorizedResponseBrief:
        """Check the given request. Asynchronous version (compatibility wrapper).

        This method provides backward compatibility with the old single-request API.
        It wraps the new batch aauthorize endpoint.

        Args:
            request: The request to check, either as a Request object or a dictionary.
            correlation_id: Optional correlation ID for tracing the request.
        Returns:
            An AuthorizedResponseBrief containing the result of the check.
        Raises:
            httpx.HTTPStatusError: If the request fails with a non-2xx status code
        """
        response = await self.aauthorize(request, correlation_id=correlation_id)
        if not response.results:
            raise ValueError("No results returned from authorize endpoint")
        result = response.results[0]
        if result.status == "failed":
            raise RuntimeError(f"Authorization failed: {result.error}")
        return result.result or AuthorizedResponseBrief(Decision.DENY)

    async def acheck_detailed(
        self, request: Request | dict[str, Any], correlation_id: str | None = None
    ) -> AuthorizedResponseDetailed:
        """Check the given request with detailed output. Asynchronous version (compatibility wrapper).

        This method provides backward compatibility with the old single-request API.
        It wraps the new batch aauthorize_detailed endpoint.

        Args:
            request: The request to check, either as a Request object or a dictionary.
            correlation_id: Optional correlation ID for tracing the request.
        Returns:
            An AuthorizedResponseDetailed containing the detailed result of the check.
        Raises:
            httpx.HTTPStatusError: If the request fails with a non-2xx status code
        """
        response = await self.aauthorize_detailed(
            request, correlation_id=correlation_id
        )
        if not response.results:
            raise ValueError("No results returned from authorize endpoint")
        result = response.results[0]
        if result.status == "failed":
            raise RuntimeError(f"Authorization failed: {result.error}")
        return result.result or AuthorizedResponseDetailed(Decision.DENY, None, None)

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
