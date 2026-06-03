def test_imports():
    from deep_scout.cli import cli, _print_remediation_summary
    from deep_scout.reporting.base import Finding

    assert isinstance(cli, object)
    assert Finding is not None
    assert callable(_print_remediation_summary)
