from packageguard import CompatReport
from packageguard.cache.aerospike_cache import PackageCache
from packageguard.resolver.dependency_resolver import CompatAgent


def test_compat_report_to_dict_serialization():
    report = CompatReport(
        status="resolved",
        resolved_versions={"fastapi": "0.110.0"},
        conflicts=["none"],
        suggestions=["pin exact versions"],
        attempts=2,
    )

    assert report.to_dict() == {
        "status": "resolved",
        "resolved_versions": {"fastapi": "0.110.0"},
        "conflicts": ["none"],
        "suggestions": ["pin exact versions"],
        "attempts": 2,
    }


def test_compat_agent_can_be_instantiated():
    agent = CompatAgent()

    assert isinstance(agent, CompatAgent)
    assert agent.max_attempts == 5


def test_package_cache_falls_back_to_memory_when_aerospike_unavailable():
    cache = PackageCache(host="127.0.0.1", port=3999, namespace="packageguard")

    assert cache.connected is False
    assert cache._client is None
