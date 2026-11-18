from sober.core.suppress import build_suppression_map, is_suppressed, parse_line_suppression


def test_ignore_all_python():
    assert parse_line_suppression("x = 1  # sober: ignore") == (True, frozenset())


def test_ignore_specific_rules():
    all_flag, ids = parse_line_suppression("x = 1  # sober: ignore[SOBER-CRY001, SOBER-REL001]")
    assert all_flag is False
    assert ids == frozenset({"SOBER-CRY001", "SOBER-REL001"})


def test_ignore_js_comments():
    assert parse_line_suppression("fetch(u) // sober: ignore")[0] is True
    assert parse_line_suppression("fetch(u) /* sober: ignore[SOBER-REL002] */")[1] == frozenset({"SOBER-REL002"})


def test_no_directive():
    assert parse_line_suppression("x = 1  # normal comment") == (False, frozenset())


def test_build_map_and_is_suppressed():
    lines = [
        "import random",
        "token = random.randint(0, 9)  # sober: ignore[SOBER-CRY001]",
        "requests.get(u)  # sober: ignore",
    ]
    smap = build_suppression_map(lines)
    assert set(smap) == {2, 3}
    assert is_suppressed("SOBER-CRY001", 2, smap) is True
    assert is_suppressed("SOBER-REL001", 2, smap) is False
    assert is_suppressed("SOBER-REL001", 3, smap) is True
    assert is_suppressed("SOBER-SEC001", 1, smap) is False
