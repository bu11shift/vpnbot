import asyncio
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import urlparse, urlunparse

from marzban_api_client import AuthenticatedClient, Client
from marzban_api_client.api.admin import admin_token
from marzban_api_client.models.body_admin_token_api_admin_token_post import (
    BodyAdminTokenApiAdminTokenPost,
)


class MarzClientCache:
    def __init__(self, base_url: str, config, logger):
        self._client: Optional[AuthenticatedClient] = None
        self._exp_at: Optional[datetime] = None
        self._base_url: str = base_url
        self._config = config
        self._logger = logger
        self._token: str = ''

    async def get_client(self):
        if not self._client or self._exp_at < datetime.now():
            self._logger.info(f'Get new token')
            token, resolved_base_url = await self.get_token()
            self._token = token
            self._base_url = resolved_base_url
            self._exp_at = datetime.now() + timedelta(minutes=self._config.marzban.token_expire - 1)
            self._client = AuthenticatedClient(
                base_url=self._base_url,
                token=self._token,
                verify_ssl=self._config.marzban.verify_ssl
            )
            self._logger.info(f'Set new client object')
        self._logger.info(f'We have client object')
        return self._client

    def _candidate_base_urls(self) -> list[str]:
        base_urls = [self._base_url]
        parsed = urlparse(self._base_url)
        hostname = parsed.hostname
        if hostname == 'marzban':
            for fallback_host in ('host.docker.internal', '127.0.0.1', 'localhost'):
                if fallback_host == hostname:
                    continue
                netloc = fallback_host
                if parsed.port:
                    netloc = f'{fallback_host}:{parsed.port}'
                candidate = urlunparse(
                    (parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)
                )
                if candidate not in base_urls:
                    base_urls.append(candidate)
        return base_urls

    async def get_token(self):
        attempts = 3
        delay_seconds = 2
        last_error: Exception | None = None
        candidate_urls = self._candidate_base_urls()
        for candidate_url in candidate_urls:
            for attempt in range(1, attempts + 1):
                try:
                    login_data = BodyAdminTokenApiAdminTokenPost(
                        username=self._config.marzban.username,
                        password=self._config.marzban.password,
                    )
                    async with Client(
                        base_url=candidate_url,
                        verify_ssl=self._config.marzban.verify_ssl,
                        follow_redirects=True,
                    ) as client:
                        response = await admin_token.asyncio_detailed(
                            client=client,
                            body=login_data,
                        )
                        token = response.parsed
                        access_token = token.access_token if token else None
                        if not access_token:
                            response_body = ""
                            if response.content:
                                response_body = response.content.decode("utf-8", errors="replace")
                            raise RuntimeError(
                                f"Token request returned empty token for {candidate_url}. "
                                f"status={response.status_code}, body={response_body[:500]!r}"
                            )
                        if candidate_url != self._base_url:
                            self._logger.warning(
                                f'Using fallback Marzban URL: {candidate_url} (initial: {self._base_url})'
                            )
                        return access_token, candidate_url
                except Exception as e:
                    last_error = e
                    if attempt == attempts:
                        break
                    self._logger.warning(
                        f"Token request failed ({attempt}/{attempts}) for {candidate_url}: {e!r}. "
                        f"Retrying in {delay_seconds}s"
                    )
                    await asyncio.sleep(delay_seconds)
        self._logger.error(f"Error getting token from {candidate_urls}: {last_error!r}")
        raise last_error
