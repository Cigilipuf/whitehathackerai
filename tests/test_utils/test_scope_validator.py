"""Tests for ScopeValidator — safety-critical scope enforcement."""

import asyncio

from src.utils.scope_validator import ScopeValidator, ScopeDefinition, ScopeTarget


def _make_validator(
    targets=None, excluded=None, excluded_paths=None, allow_ip=False,
):
    scope = ScopeDefinition(
        program_name="test",
        targets=targets or [],
        excluded_targets=excluded or [],
        excluded_paths=excluded_paths or [],
        allow_ip_resolution=allow_ip,
    )
    return ScopeValidator(scope)


# ── Domain scope ─────────────────────────────────────────

def test_exact_domain_in_scope():
    v = _make_validator(targets=[ScopeTarget(value="example.com", target_type="domain")])
    assert v.is_in_scope("example.com")
    assert v.is_in_scope("https://example.com/path")


def test_subdomain_in_scope():
    v = _make_validator(targets=[ScopeTarget(value="example.com", target_type="domain")])
    assert v.is_in_scope("sub.example.com")
    assert v.is_in_scope("deep.sub.example.com")


def test_unrelated_domain_rejected():
    v = _make_validator(targets=[ScopeTarget(value="example.com", target_type="domain")])
    assert not v.is_in_scope("evil.com")
    assert not v.is_in_scope("notexample.com")


def test_wildcard_scope():
    v = _make_validator(targets=[ScopeTarget(value="*.example.com", target_type="wildcard")])
    assert v.is_in_scope("sub.example.com")
    assert v.is_in_scope("example.com")  # base domain also matches


def test_empty_target_rejected():
    v = _make_validator(targets=[ScopeTarget(value="example.com", target_type="domain")])
    valid, reason = v.validate_target("")
    assert not valid
    assert "Empty" in reason


# ── Exclusions ───────────────────────────────────────────

def test_excluded_domain():
    v = _make_validator(
        targets=[ScopeTarget(value="example.com", target_type="domain")],
        excluded=[ScopeTarget(value="admin.example.com", include=False)],
    )
    assert v.is_in_scope("example.com")
    assert not v.is_in_scope("admin.example.com")


def test_excluded_path():
    v = _make_validator(
        targets=[ScopeTarget(value="example.com", target_type="domain")],
        excluded_paths=["/admin"],
    )
    assert v.is_in_scope("https://example.com/api")
    assert not v.is_in_scope("https://example.com/admin/panel")


# ── IP scope ─────────────────────────────────────────────

def test_ip_in_scope():
    v = _make_validator(targets=[ScopeTarget(value="192.168.1.1", target_type="ip")])
    assert v.is_in_scope("192.168.1.1")
    assert not v.is_in_scope("192.168.1.2")


def test_cidr_scope():
    v = _make_validator(targets=[ScopeTarget(value="10.0.0.0/24", target_type="cidr")])
    assert v.is_in_scope("10.0.0.1")
    assert v.is_in_scope("10.0.0.254")
    assert not v.is_in_scope("10.0.1.1")


# ── URL scope ────────────────────────────────────────────

def test_url_target_type():
    v = _make_validator(targets=[ScopeTarget(value="https://api.example.com", target_type="url")])
    assert v.is_in_scope("https://api.example.com/v1/data")


# ── Batch operations ─────────────────────────────────────

def test_filter_in_scope():
    v = _make_validator(targets=[ScopeTarget(value="example.com", target_type="domain")])
    filtered = v.filter_in_scope(["example.com", "evil.com", "sub.example.com"])
    assert filtered == ["example.com", "sub.example.com"]


def test_validate_targets_batch():
    v = _make_validator(targets=[ScopeTarget(value="example.com", target_type="domain")])
    results = v.validate_targets(["example.com", "evil.com"])
    assert results[0][1] is True
    assert results[1][1] is False


# ── Redirect scope ───────────────────────────────────────

def test_redirect_scope_allowed():
    v = _make_validator(targets=[ScopeTarget(value="example.com", target_type="domain")])
    assert v.check_redirect_scope("https://example.com/a", "https://example.com/b")
    assert not v.check_redirect_scope("https://example.com/a", "https://evil.com/b")


def test_redirect_scope_disabled():
    scope = ScopeDefinition(
        program_name="test",
        targets=[ScopeTarget(value="example.com", target_type="domain")],
        follow_redirects_in_scope=False,
    )
    v = ScopeValidator(scope)
    assert not v.check_redirect_scope("https://example.com/a", "https://example.com/b")


# ── Bare path rejection ─────────────────────────────────

def test_bare_path_rejected():
    v = _make_validator(targets=[ScopeTarget(value="example.com", target_type="domain")])
    assert not v.is_in_scope("/api/data")


# ── from_dict ────────────────────────────────────────────

def test_from_dict():
    data = {
        "program_name": "test_program",
        "targets": [
            {"value": "example.com", "type": "domain"},
            {"value": "*.cdn.example.com", "type": "wildcard"},
        ],
        "excluded": [
            {"value": "admin.example.com"},
        ],
        "excluded_paths": ["/admin"],
    }
    v = ScopeValidator.from_dict(data)
    assert v.is_in_scope("example.com")
    assert v.is_in_scope("img.cdn.example.com")
    assert not v.is_in_scope("admin.example.com")
    assert not v.is_in_scope("https://example.com/admin/page")


def test_from_dict_exclusions_key():
    """Support 'exclusions' as alternative to 'excluded'."""
    data = {
        "targets": [{"value": "example.com"}],
        "exclusions": [{"value": "blocked.example.com"}],
    }
    v = ScopeValidator.from_dict(data)
    assert not v.is_in_scope("blocked.example.com")


def test_from_dict_string_exclusions():
    """Excluded can be plain strings."""
    data = {
        "targets": [{"value": "example.com"}],
        "excluded": [{"value": "blocked.example.com"}],
    }
    v = ScopeValidator.from_dict(data)
    assert not v.is_in_scope("blocked.example.com")


# ── Async ────────────────────────────────────────────────

def test_async_scope_check():
    v = _make_validator(targets=[ScopeTarget(value="example.com", target_type="domain")])
    result = asyncio.run(v.is_in_scope_async("example.com"))
    assert result is True


# ── Properties ───────────────────────────────────────────

def test_scope_definition_properties():
    scope = ScopeDefinition(
        targets=[
            ScopeTarget(value="example.com", target_type="domain"),
            ScopeTarget(value="*.cdn.com", target_type="wildcard"),
        ],
        excluded_targets=[ScopeTarget(value="evil.com", include=False)],
    )
    assert "example.com" in scope.in_scope_domains
    assert "*.cdn.com" in scope.in_scope_domains
    assert "evil.com" in scope.out_of_scope_domains
