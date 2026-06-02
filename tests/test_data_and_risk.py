"""Tests for data collection layer and risk scoring."""

import json
import pytest

from code_sentinel.collector.diff_parser import (
    ChangeSet, ChangedFile, ChangeType, parse_diff,
)
from code_sentinel.collector.dep_scanner import (
    DepInfo, DepDiff, DependencyChange,
    parse_deps, compare_deps, scan_dependency_changes,
)
from code_sentinel.collector.codeowners import (
    CodeOwnersFile, parse_codeowners, match_files_to_owners,
)
from code_sentinel.risk.rules import (
    Rule, RuleSet, evaluate_condition, evaluate_rules, load_rules_from_toml,
)
from code_sentinel.risk.scorer import (
    RiskLevel, RiskScore, assess_risk, load_rules,
)


# ---- diff_parser tests ----

class TestDiffParser:
    def test_basic_modify(self):
        diff = (
            "--- a/foo.py\n"
            "+++ b/foo.py\n"
            "@@ -1,3 +1,5 @@ def hello():\n"
            " hello\n"
            "+world\n"
            "+added\n"
            " end\n"
        )
        cs = parse_diff(diff)
        assert cs.total_files == 1
        assert cs.files[0].lines_added == 2
        assert cs.files[0].lines_deleted == 0
        assert cs.files[0].change_type == ChangeType.MODIFY

    def test_new_file(self):
        diff = (
            "new file mode 100644\n"
            "--- /dev/null\n"
            "+++ b/new.py\n"
            "@@ -0,0 +1,3 @@\n"
            "+line1\n"
            "+line2\n"
            "+line3\n"
        )
        cs = parse_diff(diff)
        assert cs.total_files == 1
        assert cs.files[0].change_type == ChangeType.ADD
        assert cs.files[0].lines_added == 3

    def test_deleted_file(self):
        diff = (
            "deleted file mode 100644\n"
            "--- a/old.py\n"
            "+++ /dev/null\n"
            "@@ -1,3 +0,0 @@\n"
            "-line1\n"
            "-line2\n"
            "-line3\n"
        )
        cs = parse_diff(diff)
        assert cs.total_files == 1
        assert cs.files[0].change_type == ChangeType.DELETE
        assert cs.files[0].lines_deleted == 3

    def test_function_detection(self):
        diff = (
            "--- a/calc.py\n"
            "+++ b/calc.py\n"
            "@@ -1,3 +1,7 @@\n"
            " import math\n"
            "+def add(a, b):\n"
            "+    return a + b\n"
            "+\n"
            "+class Calculator:\n"
            "+    pass\n"
            " end\n"
        )
        cs = parse_diff(diff)
        f = cs.files[0]
        assert "add" in f.changed_functions
        assert "Calculator" in f.changed_classes

    def test_touches(self):
        diff = (
            "--- a/src/auth/login.py\n"
            "+++ b/src/auth/login.py\n"
            "@@ -1,2 +1,3 @@\n"
            " x\n"
            "+y\n"
        )
        cs = parse_diff(diff)
        assert cs.touches("auth/") is True
        assert cs.touches("payment/") is False

    def test_paths(self):
        diff = (
            "--- a/a.py\n"
            "+++ b/a.py\n"
            "@@ -1,2 +1,3 @@\n"
            " x\n"
            "+y\n"
            "--- b/b.py\n"
            "+++ b/b.py\n"
            "@@ -1,2 +1,3 @@\n"
            " x\n"
            "+y\n"
        )
        cs = parse_diff(diff)
        assert cs.paths() == ["a.py", "b.py"]


# ---- dep_scanner tests ----

class TestDepScanner:
    def test_package_json_compare(self):
        old = json.dumps({"dependencies": {"express": "4.17.1", "lodash": "4.17.21"}})
        new = json.dumps({"dependencies": {"express": "4.18.0", "axios": "1.4.0"}})
        dc = scan_dependency_changes("package.json", old, new)
        assert dc is not None
        assert dc.has_new_deps
        assert any(d.name == "axios" for d in dc.added)
        assert any(d.name == "lodash" for d in dc.removed)
        assert any(d.name == "express" for d in dc.upgraded)

    def test_requirements_txt(self):
        old = "flask==2.0.0\nrequests==2.28.0\n"
        new = "flask==3.0.0\nrequests==2.31.0\nhttpx==0.27.0\n"
        dc = scan_dependency_changes("requirements.txt", old, new)
        assert dc is not None
        assert len(dc.added) == 1
        assert dc.added[0].name == "httpx"

    def test_go_mod(self):
        old = "module m\ngo 1.21\nrequire (\n\tgithub.com/gin v1.9.0\n)\n"
        new = "module m\ngo 1.22\nrequire (\n\tgithub.com/gin v1.10.0\n\tgithub.com/pkg v0.9.1\n)\n"
        dc = scan_dependency_changes("go.mod", old, new)
        assert dc is not None
        assert len(dc.upgraded) == 1
        assert len(dc.added) == 1

    def test_unknown_file(self):
        assert scan_dependency_changes("README.md", "", "new") is None

    def test_no_changes(self):
        old = json.dumps({"dependencies": {"express": "4.17.1"}})
        new = json.dumps({"dependencies": {"express": "4.17.1"}})
        dc = scan_dependency_changes("package.json", old, new)
        assert dc is None  # no changes

    def test_version_comparison(self):
        old = json.dumps({"dependencies": {"a": "1.0.0", "b": "2.0.0"}})
        new = json.dumps({"dependencies": {"a": "1.0.1", "b": "1.9.0"}})
        dc = scan_dependency_changes("package.json", old, new)
        assert dc is not None
        assert len(dc.upgraded) == 1  # a
        assert len(dc.downgraded) == 1  # b


# ---- codeowners tests ----

class TestCodeOwners:
    def test_basic_parse(self):
        content = "*.py @backend\n/src/auth/ @security @alice\n"
        co = parse_codeowners(content)
        assert len(co.rules) == 2
        assert co.rules[0].owners == ["@backend"]

    def test_find_owners(self):
        content = "*.py @backend\n/src/auth/ @security @alice\n"
        co = parse_codeowners(content)
        owners = co.find_owners("src/auth/login.py")
        assert "@security" in owners
        assert "@alice" in owners

    def test_last_match_wins(self):
        content = "*.py @backend\n/src/auth/*.py @security\n"
        co = parse_codeowners(content)
        owners = co.find_owners("src/auth/login.py")
        assert "@security" in owners
        assert "@backend" not in owners  # last match wins

    def test_comments_and_blanks(self):
        content = "# comment\n\n*.py @backend\n# another\n*.js @frontend\n"
        co = parse_codeowners(content)
        assert len(co.rules) == 2

    def test_match_files_to_owners(self):
        content = "*.py @backend\n/docs/ @docs\n"
        co = parse_codeowners(content)
        results = match_files_to_owners(co, ["main.py", "docs/readme.md", "Cargo.toml"])
        assert results[0][1] == ["@backend"]
        assert results[1][1] == ["@docs"]
        assert results[2][1] == []


# ---- risk rules tests ----

class TestRules:
    def test_compare_condition(self):
        assert evaluate_condition("modified_files > 10", {"modified_files": 15}) is True
        assert evaluate_condition("modified_files > 10", {"modified_files": 5}) is False
        assert evaluate_condition("modified_files >= 10", {"modified_files": 10}) is True
        assert evaluate_condition("modified_files < 5", {"modified_files": 3}) is True
        assert evaluate_condition("modified_files <= 5", {"modified_files": 5}) is True
        assert evaluate_condition("modified_files == 5", {"modified_files": 5}) is True
        assert evaluate_condition("modified_files != 5", {"modified_files": 6}) is True

    def test_touches_condition(self):
        ctx = {"_file_paths": ["src/payment/bill.py", "README.md"]}
        assert evaluate_condition("touches('payment/')", ctx) is True
        assert evaluate_condition("touches('auth/')", ctx) is False

    def test_boolean_field(self):
        assert evaluate_condition("adds_new_dependency", {"adds_new_dependency": True}) is True
        assert evaluate_condition("adds_new_dependency", {"adds_new_dependency": False}) is False
        assert evaluate_condition("missing_field", {}) is False

    def test_float_comparison(self):
        assert evaluate_condition("density > 0.1", {"density": 0.15}) is True
        assert evaluate_condition("density > 0.1", {"density": 0.05}) is False

    def test_load_rules_from_toml(self):
        data = {
            "settings": {"low_risk_max": 5, "medium_risk_max": 10},
            "rules": [
                {"name": "r1", "description": "Rule 1", "condition": "x > 1", "score_delta": 2, "tag": "t"},
            ],
        }
        rs = load_rules_from_toml(data)
        assert rs.low_risk_max == 5
        assert rs.medium_risk_max == 10
        assert len(rs.rules) == 1
        assert rs.rules[0].name == "r1"

    def test_evaluate_rules(self):
        rs = RuleSet(
            rules=[
                Rule(name="r1", description="big", condition="x > 10", score_delta=2, tag="size"),
                Rule(name="r2", description="small", condition="x < 5", score_delta=1, tag="tiny"),
                Rule(name="r3", description="disabled", condition="x > 0", score_delta=5, tag="off", enabled=False),
            ],
        )
        score, triggered, tags = evaluate_rules(rs, {"x": 15})
        assert score == 2
        assert len(triggered) == 1
        assert "size" in tags

    def test_unknown_function_raises(self):
        with pytest.raises(ValueError):
            evaluate_condition("bogus('x')", {})


# ---- risk scorer tests ----

class TestScorer:
    def test_assess_low_risk(self):
        cs = ChangeSet(total_files=1, total_additions=2, total_deletions=0)
        cs.files.append(ChangedFile(path="README.md"))
        rs = RuleSet(low_risk_max=3, medium_risk_max=6, rules=[
            Rule(name="big", description="big", condition="modified_files > 10", score_delta=2, tag="size"),
        ])
        result = assess_risk(changeset=cs, ruleset=rs)
        assert result.level == RiskLevel.LOW
        assert result.score == 0

    def test_assess_high_risk(self):
        cs = ChangeSet(total_files=50, total_additions=500, total_deletions=100)
        for i in range(50):
            cs.files.append(ChangedFile(path=f"src/auth/file{i}.py"))
        rs = RuleSet(low_risk_max=3, medium_risk_max=6, rules=[
            Rule(name="big", description="big PR", condition="modified_files > 10", score_delta=4, tag="size"),
            Rule(name="auth", description="touches auth", condition="touches('auth/')", score_delta=5, tag="security"),
        ])
        result = assess_risk(changeset=cs, ruleset=rs)
        assert result.level == RiskLevel.HIGH
        assert result.score == 9
        assert len(result.triggered_rules) == 2

    def test_summary(self):
        rs = RiskScore(level=RiskLevel.MEDIUM, score=4, triggered_rules=["r1"], tags=["t1"])
        s = rs.summary()
        assert "MEDIUM" in s
        assert "4" in s

    def test_load_default_rules(self):
        rs = load_rules()
        assert len(rs.rules) > 10
        assert rs.low_risk_max == 3
        assert rs.medium_risk_max == 6

    def test_e2e_with_dep_changes(self):
        cs = ChangeSet(total_files=3, total_additions=20, total_deletions=5)
        cs.files.append(ChangedFile(path="src/payment/billing.py"))
        dep = DependencyChange(
            file_path="package.json",
            file_type="package.json",
            added=[DepDiff(name="axios", change_type="added", new_version="1.0.0")],
        )
        result = assess_risk(changeset=cs, dep_changes=[dep])
        assert result.score > 0
        assert any("payment" in t for t in result.triggered_rules)
