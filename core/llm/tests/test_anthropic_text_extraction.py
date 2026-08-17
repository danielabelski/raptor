"""AnthropicProvider.generate() must extract the first TEXT block —
reasoning-tier models prepend thinking blocks, so content[0] is not
reliably text.  Observed live: a response shaped
[thinking, text("OK")] failed with "non-text content block: thinking".
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest


def _response(*blocks):
    return SimpleNamespace(
        content=list(blocks),
        stop_reason="end_turn",
        usage=SimpleNamespace(
            input_tokens=5, output_tokens=3,
            cache_creation_input_tokens=0, cache_read_input_tokens=0,
        ),
        model="claude-sonnet-5",
    )


def _generate_with(response):
    from core.llm.config import ModelConfig
    from core.llm.providers import AnthropicProvider

    provider = AnthropicProvider(ModelConfig(
        provider="anthropic", model_name="claude-sonnet-5", api_key="k",
    ))
    provider._caching_warning_emitted = True
    provider.client = SimpleNamespace(
        messages=SimpleNamespace(create=lambda **kw: response),
    )
    return provider.generate("ping")


def test_thinking_block_before_text_is_skipped():
    thinking = SimpleNamespace(type="thinking", thinking="…")
    text = SimpleNamespace(type="text", text="OK")
    out = _generate_with(_response(thinking, text))
    assert out.content == "OK"


def test_plain_text_first_still_works():
    text = SimpleNamespace(type="text", text="hello")
    out = _generate_with(_response(text))
    assert out.content == "hello"


def test_no_text_block_raises_with_block_types():
    thinking = SimpleNamespace(type="thinking", thinking="…")
    with pytest.raises(RuntimeError) as e:
        _generate_with(_response(thinking))
    assert "thinking" in str(e.value)


def test_empty_content_raises():
    with pytest.raises(RuntimeError):
        _generate_with(_response())
