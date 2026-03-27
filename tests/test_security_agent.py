from packageguard import Finding, ScanReport


def test_compute_score_single_critical_warning():
    report = ScanReport(
        package_name="demo",
        version="0.1.0",
        findings=[
            Finding(
                severity="critical",
                category="pth_injection",
                description="Critical finding",
            )
        ],
    )

    report.compute_score()

    assert report.risk_score == 40
    assert report.verdict == "WARNING"


def test_compute_score_two_critical_blocked():
    report = ScanReport(
        package_name="demo",
        version="0.1.0",
        findings=[
            Finding(severity="critical", category="pth_injection", description="One"),
            Finding(severity="critical", category="credential_theft", description="Two"),
        ],
    )

    report.compute_score()

    assert report.risk_score == 80
    assert report.verdict == "BLOCKED"


def test_compute_score_three_low_safe():
    report = ScanReport(
        package_name="demo",
        version="0.1.0",
        findings=[
            Finding(severity="low", category="suspicious_metadata", description="One"),
            Finding(severity="low", category="suspicious_metadata", description="Two"),
            Finding(severity="low", category="suspicious_metadata", description="Three"),
        ],
    )

    report.compute_score()

    assert report.risk_score == 9
    assert report.verdict == "SAFE"


def test_scan_report_json_roundtrip():
    report = ScanReport(
        package_name="demo-litellm-evil",
        version="0.0.1",
        findings=[
            Finding(
                severity="high",
                category="install_hook",
                description="Overridden install hook",
                file="setup.py",
                line=12,
                evidence="cmdclass install override",
            )
        ],
        scan_duration=1.23,
        cached=True,
    )
    report.compute_score()

    loaded = ScanReport.from_json(report.to_json())

    assert loaded.package_name == report.package_name
    assert loaded.version == report.version
    assert loaded.risk_score == report.risk_score
    assert loaded.verdict == report.verdict
    assert loaded.findings[0].description == report.findings[0].description
    assert loaded.findings[0].file == "setup.py"
    assert loaded.cached is True


def test_finding_to_dict_truncates_evidence():
    finding = Finding(
        severity="medium",
        category="code_obfuscation",
        description="Encoded payload",
        evidence="x" * 700,
    )

    payload = finding.to_dict()

    assert len(payload["evidence"]) == 500
    assert payload["evidence"] == "x" * 500
