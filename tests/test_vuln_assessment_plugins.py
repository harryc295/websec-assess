from tests.conftest import make_config, make_ctx
from websec_assess.plugins.vuln_assessment.cookie_analysis import CookieAnalysisPlugin
from websec_assess.plugins.vuln_assessment.security_headers import SecurityHeadersPlugin


async def test_security_headers_flags_missing_headers(tmp_path, local_server):
    config = make_config(tmp_path)
    ctx = await make_ctx(config, local_server, "127.0.0.1", SecurityHeadersPlugin.name)
    try:
        result = await SecurityHeadersPlugin().run(ctx)
    finally:
        await ctx.http.aclose()

    titles = {f.title for f in result.findings}
    assert any("x-content-type-options" in t for t in titles)
    assert any("x-frame-options" in t for t in titles)
    assert not result.errors


async def test_cookie_analysis_flags_missing_flags(tmp_path, local_server):
    config = make_config(tmp_path)
    ctx = await make_ctx(config, local_server, "127.0.0.1", CookieAnalysisPlugin.name)
    try:
        result = await CookieAnalysisPlugin().run(ctx)
    finally:
        await ctx.http.aclose()

    titles = " ".join(f.title for f in result.findings)
    assert "missing HttpOnly" in titles
    assert "session" in ctx.state.cookies
