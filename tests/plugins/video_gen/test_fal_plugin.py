"""Tests for the FAL video gen plugin — family routing, payload shape."""

from __future__ import annotations

import sys
import types

import pytest

from agent import video_gen_registry


@pytest.fixture(autouse=True)
def _reset_registry():
    video_gen_registry._reset_for_tests()
    yield
    video_gen_registry._reset_for_tests()


def test_fal_provider_registers():
    from plugins.video_gen.fal import FALVideoGenProvider, DEFAULT_MODEL

    provider = FALVideoGenProvider()
    video_gen_registry.register_provider(provider)

    assert video_gen_registry.get_provider("fal") is provider
    assert provider.display_name == "FAL"
    # DEFAULT_MODEL is the cheap-tier default
    assert provider.default_model() == DEFAULT_MODEL
    assert DEFAULT_MODEL in {"pixverse-v6", "ltx-2.3"}


def test_fal_family_catalog():
    """Each family declares both endpoints. The catalog covers the
    cheap + premium tiers Teknium listed."""
    from plugins.video_gen.fal import FAL_FAMILIES

    expected = {
        # cheap
        "ltx-2.3", "pixverse-v6",
        # premium
        "veo3.1", "seedance-2.0", "kling-v3-4k", "happy-horse",
    }
    assert expected.issubset(set(FAL_FAMILIES.keys())), (
        f"missing families: {expected - set(FAL_FAMILIES.keys())}"
    )
    for fid, meta in FAL_FAMILIES.items():
        assert meta.get("text_endpoint"), f"{fid} missing text_endpoint"
        assert meta.get("image_endpoint"), f"{fid} missing image_endpoint"
        assert meta["text_endpoint"] != meta["image_endpoint"]
        assert meta.get("tier") in {"cheap", "premium"}, (
            f"{fid} has invalid tier"
        )


def test_kling_4k_uses_start_image_url():
    """Kling v3 4K's image-to-video endpoint expects start_image_url,
    not image_url. The family must declare image_param_key='start_image_url'."""
    from plugins.video_gen.fal import FAL_FAMILIES, _build_payload

    meta = FAL_FAMILIES["kling-v3-4k"]
    assert meta.get("image_param_key") == "start_image_url"
    payload = _build_payload(
        meta,
        prompt="x",
        image_url="https://example.com/i.png",
        duration=5,
        aspect_ratio="16:9",
        resolution="720p",
        negative_prompt=None,
        audio=None,
        seed=None,
    )
    assert payload.get("start_image_url") == "https://example.com/i.png"
    assert "image_url" not in payload


def test_fal_list_models_advertises_both_modalities():
    from plugins.video_gen.fal import FALVideoGenProvider

    models = FALVideoGenProvider().list_models()
    for m in models:
        assert set(m["modalities"]) == {"text", "image"}, (
            f"{m['id']} doesn't advertise both modalities — every family "
            f"should have t2v + i2v"
        )


def test_fal_unavailable_without_key(monkeypatch):
    from plugins.video_gen.fal import FALVideoGenProvider

    monkeypatch.delenv("FAL_KEY", raising=False)
    monkeypatch.setattr("plugins.video_gen.fal._resolve_managed_fal_gateway", lambda: None)
    assert FALVideoGenProvider().is_available() is False


def test_fal_available_with_managed_gateway(monkeypatch):
    from plugins.video_gen import fal as fal_plugin
    from plugins.video_gen.fal import FALVideoGenProvider

    monkeypatch.delenv("FAL_KEY", raising=False)
    fake_fal = types.ModuleType("fal_client")
    monkeypatch.setitem(sys.modules, "fal_client", fake_fal)
    fal_plugin._fal_client = None
    monkeypatch.setattr(
        fal_plugin,
        "_resolve_managed_fal_gateway",
        lambda: types.SimpleNamespace(
            gateway_origin="http://127.0.0.1:3009",
            nous_user_token="nous-token",
        ),
    )

    assert FALVideoGenProvider().is_available() is True


def test_fal_generate_requires_fal_key_or_managed_gateway(monkeypatch):
    from plugins.video_gen.fal import FALVideoGenProvider

    monkeypatch.delenv("FAL_KEY", raising=False)
    monkeypatch.setattr("plugins.video_gen.fal._resolve_managed_fal_gateway", lambda: None)
    result = FALVideoGenProvider().generate("a happy dog")
    assert result["success"] is False
    assert result["error_type"] == "auth_required"


def test_fal_generate_uses_managed_gateway_when_direct_key_absent(monkeypatch):
    from plugins.video_gen import fal as fal_plugin
    from plugins.video_gen.fal import FALVideoGenProvider

    captured = {}

    fake_fal = types.ModuleType("fal_client")

    def _subscribe(endpoint, arguments=None, with_logs=False):
        raise AssertionError("managed FAL video generation should not call fal_client.subscribe")

    class FakeResponse:
        def json(self):
            return {
                "request_id": "req-video-123",
                "response_url": "http://127.0.0.1:3009/fal-ai/veo3.1/requests/req-video-123",
                "status_url": "http://127.0.0.1:3009/fal-ai/veo3.1/requests/req-video-123/status",
                "cancel_url": "http://127.0.0.1:3009/fal-ai/veo3.1/requests/req-video-123/cancel",
            }

    def _maybe_retry_request(client, method, url, json=None, timeout=None, headers=None):
        captured["http_client"] = client
        captured["method"] = method
        captured["url"] = url
        captured["arguments"] = json
        captured["timeout"] = timeout
        captured["headers"] = headers
        return FakeResponse()

    class SyncRequestHandle:
        def __init__(self, request_id, response_url, status_url, cancel_url, client):
            captured["request_id"] = request_id
            captured["response_url"] = response_url
            captured["status_url"] = status_url
            captured["cancel_url"] = cancel_url
            captured["handle_client"] = client

        def get(self):
            return {"video": {"url": "https://fal.media/out.mp4", "content_type": "video/mp4"}}

    class SyncClient:
        def __init__(self, key=None, default_timeout=120.0):
            captured["client_key"] = key
            self.default_timeout = default_timeout
            self._client = object()

    fake_fal.subscribe = _subscribe  # type: ignore[attr-defined]
    fake_fal.SyncClient = SyncClient  # type: ignore[attr-defined]
    fake_fal.client = types.SimpleNamespace(
        _maybe_retry_request=_maybe_retry_request,
        _raise_for_status=lambda response: None,
        SyncRequestHandle=SyncRequestHandle,
    )
    monkeypatch.setitem(sys.modules, "fal_client", fake_fal)

    monkeypatch.delenv("FAL_KEY", raising=False)
    fal_plugin._fal_client = None
    fal_plugin._managed_fal_client = None
    fal_plugin._managed_fal_client_config = None
    monkeypatch.setattr(fal_plugin.uuid, "uuid4", lambda: "video-submit-123")
    monkeypatch.setattr(
        fal_plugin,
        "_resolve_managed_fal_gateway",
        lambda: types.SimpleNamespace(
            gateway_origin="http://127.0.0.1:3009",
            nous_user_token="nous-token",
        ),
    )

    result = FALVideoGenProvider().generate(
        "a dog running",
        model="veo3.1",
        duration=8,
        aspect_ratio="16:9",
        resolution="1080p",
        audio=True,
    )

    assert result["success"] is True
    assert result["video"] == "https://fal.media/out.mp4"
    assert result["endpoint"] == "fal-ai/veo3.1"
    assert captured["client_key"] == "nous-token"
    assert captured["method"] == "POST"
    assert captured["url"] == "http://127.0.0.1:3009/fal-ai/veo3.1"
    assert captured["arguments"] == {
        "prompt": "a dog running",
        "aspect_ratio": "16:9",
        "resolution": "1080p",
        "duration": "8",
        "generate_audio": True,
    }
    assert captured["headers"] == {"x-idempotency-key": "video-submit-123"}


class TestFamilyRouting:
    """The headline behavior: image_url presence picks the endpoint."""

    @pytest.fixture
    def with_fake_fal(self, monkeypatch):
        """Stub fal_client.subscribe to capture which endpoint we hit."""
        import sys
        import types

        captured = {"endpoint": None, "arguments": None}

        fake = types.ModuleType("fal_client")
        def _subscribe(endpoint, arguments=None, with_logs=False):
            captured["endpoint"] = endpoint
            captured["arguments"] = arguments
            return {"video": {"url": "https://fake/out.mp4"}}
        fake.subscribe = _subscribe  # type: ignore
        monkeypatch.setitem(sys.modules, "fal_client", fake)

        # Reset the lazy global so it picks up our stub
        from plugins.video_gen import fal as fal_plugin
        fal_plugin._fal_client = None

        monkeypatch.setenv("FAL_KEY", "test")
        return captured

    def test_text_to_video_routes_to_text_endpoint(self, with_fake_fal):
        from plugins.video_gen.fal import FALVideoGenProvider

        result = FALVideoGenProvider().generate(
            "a dog running",
            model="pixverse-v6",
        )
        assert result["success"] is True
        assert with_fake_fal["endpoint"] == "fal-ai/pixverse/v6/text-to-video"
        assert result["modality"] == "text"
        assert with_fake_fal["arguments"]["prompt"] == "a dog running"
        assert "image_url" not in with_fake_fal["arguments"]

    def test_image_to_video_routes_to_image_endpoint(self, with_fake_fal):
        from plugins.video_gen.fal import FALVideoGenProvider

        result = FALVideoGenProvider().generate(
            "animate this dog",
            model="pixverse-v6",
            image_url="https://example.com/dog.png",
        )
        assert result["success"] is True
        assert with_fake_fal["endpoint"] == "fal-ai/pixverse/v6/image-to-video"
        assert result["modality"] == "image"
        assert with_fake_fal["arguments"]["image_url"] == "https://example.com/dog.png"

    def test_default_family_text_routing(self, with_fake_fal):
        """No model arg → DEFAULT_MODEL → text-to-video endpoint."""
        from plugins.video_gen.fal import FALVideoGenProvider, FAL_FAMILIES, DEFAULT_MODEL

        result = FALVideoGenProvider().generate("a dog")
        assert result["success"] is True
        expected_endpoint = FAL_FAMILIES[DEFAULT_MODEL]["text_endpoint"]
        assert with_fake_fal["endpoint"] == expected_endpoint

    def test_default_family_image_routing(self, with_fake_fal):
        from plugins.video_gen.fal import FALVideoGenProvider, FAL_FAMILIES, DEFAULT_MODEL

        result = FALVideoGenProvider().generate(
            "animate this",
            image_url="https://example.com/i.png",
        )
        assert result["success"] is True
        expected_endpoint = FAL_FAMILIES[DEFAULT_MODEL]["image_endpoint"]
        assert with_fake_fal["endpoint"] == expected_endpoint

    def test_unknown_family_falls_back_to_default(self, with_fake_fal):
        from plugins.video_gen.fal import FALVideoGenProvider, FAL_FAMILIES, DEFAULT_MODEL

        result = FALVideoGenProvider().generate(
            "x",
            model="not-a-real-family",
        )
        assert result["success"] is True
        expected_endpoint = FAL_FAMILIES[DEFAULT_MODEL]["text_endpoint"]
        assert with_fake_fal["endpoint"] == expected_endpoint

    def test_premium_seedance_routing(self, with_fake_fal):
        """Sanity check the premium-tier seedance routes correctly."""
        from plugins.video_gen.fal import FALVideoGenProvider

        result = FALVideoGenProvider().generate(
            "a dog",
            model="seedance-2.0",
            image_url="https://example.com/dog.png",
        )
        assert result["success"] is True
        assert with_fake_fal["endpoint"] == "bytedance/seedance-2.0/image-to-video"
        # Seedance uses regular image_url (not start_image_url)
        assert with_fake_fal["arguments"]["image_url"] == "https://example.com/dog.png"

    def test_kling_4k_remaps_image_param(self, with_fake_fal):
        """Kling v3 4K image-to-video receives start_image_url, not image_url."""
        from plugins.video_gen.fal import FALVideoGenProvider

        result = FALVideoGenProvider().generate(
            "x",
            model="kling-v3-4k",
            image_url="https://example.com/frame.png",
        )
        assert result["success"] is True
        assert with_fake_fal["endpoint"] == "fal-ai/kling-video/v3/4k/image-to-video"
        assert with_fake_fal["arguments"].get("start_image_url") == "https://example.com/frame.png"
        assert "image_url" not in with_fake_fal["arguments"]


class TestPayloadBuilder:
    def test_drops_unsupported_keys(self):
        """Veo enum-clamps duration, supports aspect+resolution+audio+neg."""
        from plugins.video_gen.fal import FAL_FAMILIES, _build_payload

        meta = FAL_FAMILIES["veo3.1"]
        p = _build_payload(
            meta,
            prompt="x",
            image_url=None,
            duration=12,           # not in enum (4,6,8) — snap to 8
            aspect_ratio="16:9",
            resolution="720p",
            negative_prompt="ugly",
            audio=True,
            seed=42,
        )
        assert p["prompt"] == "x"
        assert p["duration"] == "8"  # FAL queue API uses strings
        assert p["aspect_ratio"] == "16:9"
        assert p["resolution"] == "720p"
        assert p["generate_audio"] is True
        assert p["negative_prompt"] == "ugly"
        assert p["seed"] == 42

    def test_pixverse_range_clamps_correctly(self):
        from plugins.video_gen.fal import FAL_FAMILIES, _build_payload

        meta = FAL_FAMILIES["pixverse-v6"]
        p = _build_payload(
            meta,
            prompt="x",
            image_url="https://i.png",
            duration=99,        # over max → 15
            aspect_ratio="16:9",
            resolution="540p",
            negative_prompt=None,
            audio=None,
            seed=None,
        )
        assert p["duration"] == "15"

    def test_kling_4k_clamps_below_min(self):
        from plugins.video_gen.fal import FAL_FAMILIES, _build_payload

        meta = FAL_FAMILIES["kling-v3-4k"]
        p = _build_payload(
            meta,
            prompt="x",
            image_url="https://i.png",
            duration=1,         # below min (3) → 3
            aspect_ratio="16:9",
            resolution="720p",
            negative_prompt=None,
            audio=None,
            seed=None,
        )
        assert p["duration"] == "3"

    def test_ltx_omits_duration_aspect_resolution(self):
        """LTX 2.3 doesn't declare duration/aspect/resolution enums —
        the payload should NOT include those keys (let FAL default)."""
        from plugins.video_gen.fal import FAL_FAMILIES, _build_payload

        meta = FAL_FAMILIES["ltx-2.3"]
        p = _build_payload(
            meta,
            prompt="x",
            image_url=None,
            duration=8,
            aspect_ratio="16:9",
            resolution="720p",
            negative_prompt="ugly",
            audio=True,
            seed=None,
        )
        assert "duration" not in p
        assert "aspect_ratio" not in p
        assert "resolution" not in p
        # But audio + negative are advertised
        assert p["generate_audio"] is True
        assert p["negative_prompt"] == "ugly"

    def test_happy_horse_minimal_payload(self):
        """Happy Horse has sparse docs — payload should be minimal."""
        from plugins.video_gen.fal import FAL_FAMILIES, _build_payload

        meta = FAL_FAMILIES["happy-horse"]
        p = _build_payload(
            meta,
            prompt="a horse galloping",
            image_url=None,
            duration=8,
            aspect_ratio="16:9",
            resolution="720p",
            negative_prompt="watermark",
            audio=True,
            seed=None,
        )
        # Only prompt — no payload bloat for fields we can't verify
        assert p == {"prompt": "a horse galloping"}
