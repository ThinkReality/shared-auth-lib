"""Tests for HMAC signature computation and verification."""

from datetime import UTC, datetime, timedelta


from shared_auth_lib.services.hmac_verifier import (
    SIGNED_HEADERS,
    build_canonical_string,
    compute_signature,
    verify_signature,
)

SECRET = "test-secret-key-32-bytes-long!!!"

SAMPLE_HEADERS = {
    "X-User-ID": "550e8400-e29b-41d4-a716-446655440000",
    "X-User-Role": "ADMIN",
    "X-Tenant-ID": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "X-Correlation-ID": "corr-123",
}


class TestBuildCanonicalString:
    def test_includes_method_path_headers_timestamp(self):
        result = build_canonical_string(
            method="GET",
            path="/api/v1/listings",
            headers=SAMPLE_HEADERS,
            timestamp="2025-01-01T00:00:00+00:00",
        )
        lines = result.split("\n")
        assert lines[0] == "GET"
        assert lines[1] == "/api/v1/listings"
        assert lines[2] == SAMPLE_HEADERS["X-User-ID"]
        assert lines[3] == SAMPLE_HEADERS["X-User-Role"]
        assert lines[4] == SAMPLE_HEADERS["X-Tenant-ID"]
        assert lines[5] == SAMPLE_HEADERS["X-Correlation-ID"]
        assert lines[6] == "2025-01-01T00:00:00+00:00"

    def test_method_is_uppercased(self):
        result = build_canonical_string(
            method="get",
            path="/test",
            headers={},
            timestamp="ts",
        )
        assert result.startswith("GET\n")

    def test_missing_headers_use_empty_string(self):
        result = build_canonical_string(
            method="POST",
            path="/test",
            headers={},
            timestamp="ts",
        )
        lines = result.split("\n")
        for i in range(2, 2 + len(SIGNED_HEADERS)):
            assert lines[i] == ""

    def test_case_insensitive_header_lookup(self):
        lowercase_headers = {
            "x-user-id": "user-123",
            "x-user-role": "AGENT",
            "x-tenant-id": "tenant-456",
            "x-correlation-id": "corr-456",
        }
        result = build_canonical_string(
            method="GET",
            path="/test",
            headers=lowercase_headers,
            timestamp="ts",
        )
        lines = result.split("\n")
        assert lines[2] == "user-123"
        assert lines[3] == "AGENT"
        assert lines[4] == "tenant-456"
        assert lines[5] == "corr-456"


class TestComputeSignature:
    def test_returns_hex_string(self):
        sig = compute_signature(
            method="GET",
            path="/test",
            headers=SAMPLE_HEADERS,
            secret=SECRET,
            timestamp="2025-01-01T00:00:00+00:00",
        )
        assert isinstance(sig, str)
        assert len(sig) == 64
        int(sig, 16)

    def test_same_inputs_produce_same_signature(self):
        kwargs = dict(
            method="GET",
            path="/test",
            headers=SAMPLE_HEADERS,
            secret=SECRET,
            timestamp="2025-01-01T00:00:00+00:00",
        )
        assert compute_signature(**kwargs) == compute_signature(
            **kwargs
        )

    def test_different_secret_produces_different_signature(self):
        kwargs = dict(
            method="GET",
            path="/test",
            headers=SAMPLE_HEADERS,
            timestamp="2025-01-01T00:00:00+00:00",
        )
        sig1 = compute_signature(**kwargs, secret="secret-a")
        sig2 = compute_signature(**kwargs, secret="secret-b")
        assert sig1 != sig2

    def test_different_path_produces_different_signature(self):
        kwargs = dict(
            headers=SAMPLE_HEADERS,
            secret=SECRET,
            timestamp="2025-01-01T00:00:00+00:00",
            method="GET",
        )
        sig1 = compute_signature(**kwargs, path="/a")
        sig2 = compute_signature(**kwargs, path="/b")
        assert sig1 != sig2

    def test_different_method_produces_different_signature(self):
        kwargs = dict(
            path="/test",
            headers=SAMPLE_HEADERS,
            secret=SECRET,
            timestamp="2025-01-01T00:00:00+00:00",
        )
        sig1 = compute_signature(**kwargs, method="GET")
        sig2 = compute_signature(**kwargs, method="POST")
        assert sig1 != sig2


class TestVerifySignature:
    def _sign(self, **overrides):
        defaults = dict(
            method="GET",
            path="/test",
            headers=SAMPLE_HEADERS,
            secret=SECRET,
            timestamp=datetime.now(UTC).isoformat(),
        )
        defaults.update(overrides)
        sig = compute_signature(**defaults)
        return defaults, sig

    def test_valid_signature_passes(self):
        params, sig = self._sign()
        assert verify_signature(
            **params, signature=sig
        ) is True

    def test_wrong_signature_fails(self):
        params, _ = self._sign()
        assert verify_signature(
            **params, signature="0" * 64
        ) is False

    def test_wrong_secret_fails(self):
        params, sig = self._sign()
        params["secret"] = "wrong-secret"
        assert verify_signature(
            **params, signature=sig
        ) is False

    def test_expired_timestamp_fails(self):
        old_ts = (
            datetime.now(UTC) - timedelta(seconds=60)
        ).isoformat()
        params, sig = self._sign(timestamp=old_ts)
        assert verify_signature(
            **params,
            signature=sig,
            tolerance_seconds=30,
        ) is False

    def test_future_timestamp_within_tolerance_passes(self):
        future_ts = (
            datetime.now(UTC) + timedelta(seconds=10)
        ).isoformat()
        params, sig = self._sign(timestamp=future_ts)
        assert verify_signature(
            **params,
            signature=sig,
            tolerance_seconds=30,
        ) is True

    def test_invalid_timestamp_format_fails(self):
        params, sig = self._sign()
        params["timestamp"] = "not-a-timestamp"
        assert verify_signature(
            **params, signature=sig
        ) is False

    def test_none_timestamp_fails(self):
        params, sig = self._sign()
        params["timestamp"] = None
        assert verify_signature(
            **params, signature=sig
        ) is False

    def test_forged_tenant_id_fails(self):
        """Verify that a request with a tampered X-Tenant-ID is rejected."""
        ts = datetime.now(UTC).isoformat()
        original_headers = {
            "X-User-ID": "user-1",
            "X-User-Role": "ADMIN",
            "X-Tenant-ID": "original-tenant-id",
            "X-Correlation-ID": "c-1",
        }
        sig = compute_signature(
            method="GET",
            path="/test",
            headers=original_headers,
            secret=SECRET,
            timestamp=ts,
        )
        # Attacker forges X-Tenant-ID after signature was computed
        forged_headers = original_headers.copy()
        forged_headers["X-Tenant-ID"] = "forged-tenant-id"
        assert verify_signature(
            method="GET",
            path="/test",
            headers=forged_headers,
            secret=SECRET,
            signature=sig,
            timestamp=ts,
        ) is False

    def test_case_insensitive_headers_produce_same_result(self):
        ts = datetime.now(UTC).isoformat()
        mixed_case = {
            "X-User-ID": "user-1",
            "X-User-Role": "ADMIN",
            "X-Tenant-ID": "tenant-1",
            "X-Correlation-ID": "c-1",
        }
        lower_case = {
            "x-user-id": "user-1",
            "x-user-role": "ADMIN",
            "x-tenant-id": "tenant-1",
            "x-correlation-id": "c-1",
        }
        sig = compute_signature(
            method="GET",
            path="/test",
            headers=mixed_case,
            secret=SECRET,
            timestamp=ts,
        )
        assert verify_signature(
            method="GET",
            path="/test",
            headers=lower_case,
            secret=SECRET,
            signature=sig,
            timestamp=ts,
        ) is True
