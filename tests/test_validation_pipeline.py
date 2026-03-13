"""
Tests for the AI validation pipeline.
"""

import pytest
from unittest.mock import patch, MagicMock
from backend.validation.static_analysis import StaticAnalyzer, AnalysisResult
from backend.validation.regression import RegressionRunner, RegressionResult


# ── Static Analysis Tests ─────────────────────────────────────

class TestStaticAnalyzer:

    def test_clean_python_passes(self):
        code = "def get_user(uid):\n    return db.execute('SELECT * FROM users WHERE id=?', (uid,))\n"
        result = StaticAnalyzer(language="python").analyze(code)
        assert isinstance(result, AnalysisResult)
        assert result.passed

    def test_sql_injection_detected(self):
        code = 'def get_user(name):\n    return db.execute("SELECT * FROM users WHERE name=\'" + name + "\'")\n'
        result = StaticAnalyzer(language="python").analyze(code)
        assert not result.passed
        assert any("injection" in f.lower() or "sql" in f.lower() for f in result.findings)

    def test_empty_code_passes(self):
        result = StaticAnalyzer(language="python").analyze("")
        assert result.passed

    def test_unsupported_language_raises(self):
        with pytest.raises(ValueError, match="Unsupported language"):
            StaticAnalyzer(language="cobol")

    def test_analysis_result_has_score(self):
        result = StaticAnalyzer(language="python").analyze("x = 1\n")
        assert 0.0 <= result.score <= 1.0

    def test_multiple_findings_reported(self):
        # Code with several issues
        code = (
            "import os\n"
            "def run(cmd): os.system(cmd)\n"          # shell injection
            "password = 'hardcoded123'\n"              # hardcoded secret
        )
        result = StaticAnalyzer(language="python").analyze(code)
        assert not result.passed
        assert len(result.findings) >= 1


# ── Regression Runner Tests ───────────────────────────────────

class TestRegressionRunner:

    @patch("backend.validation.regression.subprocess.run")
    def test_all_pass_returns_success(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="5 passed", stderr="")
        runner = RegressionRunner(test_dir="tests/fixtures/passing")
        result = runner.run(patch_code="# no-op patch")
        assert isinstance(result, RegressionResult)
        assert result.passed
        assert result.failures == 0

    @patch("backend.validation.regression.subprocess.run")
    def test_failing_test_detected(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="3 passed, 2 failed", stderr="AssertionError")
        runner = RegressionRunner(test_dir="tests/fixtures/failing")
        result = runner.run(patch_code="# broken patch")
        assert not result.passed
        assert result.failures > 0

    @patch("backend.validation.regression.subprocess.run")
    def test_timeout_handled(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="pytest", timeout=120)
        runner = RegressionRunner(test_dir="tests/fixtures", timeout=120)
        result = runner.run(patch_code="# infinite loop patch")
        assert not result.passed
        assert "timeout" in result.error.lower()

    def test_result_has_duration(self):
        with patch("backend.validation.regression.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="1 passed", stderr="")
            runner = RegressionRunner(test_dir="tests/fixtures/passing")
            result = runner.run(patch_code="x = 1")
            assert result.duration_seconds >= 0
