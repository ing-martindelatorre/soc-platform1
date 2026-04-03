from app.pipeline.registry import MODULES


def test_modules_exist():

    assert "sentinel" in MODULES
    assert "snyk" in MODULES
    assert "nmap" in MODULES
    assert "fortinet" in MODULES