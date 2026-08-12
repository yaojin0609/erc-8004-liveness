"""单 host 探测上限的回归测试。

同一 host 强制 1 请求/3 秒串行，所以探测总耗时由【最大的那个 host】决定，
不是由目标总数决定。实测全量 dry-run：163,230 个目标要 182 小时，其中
evoevo.ai 一家 36,413 个目标就占了 90% 的时间。

上限必须满足三条，否则结论不可复现或不可回权：
  1. 固定种子 → 复跑抽到同一批
  2. 没超上限的 host 一个都不能少
  3. 被抽掉的要能完整拿回来（报告要按 host 规模回权）
"""

import pytest

from e8004.probe import ProbeTarget
from e8004.stages.s06_probe import apply_target_host_cap

SEED = 8004


def _targets(spec: dict[str, int]) -> list[ProbeTarget]:
    out = []
    for host, n in spec.items():
        for i in range(n):
            out.append(ProbeTarget(endpoint=f"https://{host}/svc/{i}",
                                   declared_kind="web", ref=f"1:{i}:0"))
    return out


def _hosts(ts: list[ProbeTarget]) -> dict[str, int]:
    from collections import Counter
    from e8004.probe.layers import parse_endpoint
    return Counter(parse_endpoint(t.endpoint)[0] for t in ts)


def test_cap_limits_big_hosts_and_keeps_small_ones_whole():
    ts = _targets({"big.test": 5000, "mid.test": 100, "tiny.test": 1})
    keep, dropped = apply_target_host_cap(ts, cap=2000, seed=SEED)
    kh = _hosts(keep)
    assert kh["big.test"] == 2000          # 超限的被削到上限
    assert kh["mid.test"] == 100           # 没超限的一个不少
    assert kh["tiny.test"] == 1
    assert len(dropped) == 3000
    # 全集守恒：抽样不能凭空丢目标
    assert len(keep) + len(dropped) == len(ts)


def test_cap_is_deterministic_across_runs():
    """同种子必须抽到同一批，否则两轮探测比的不是同一组端点。"""
    ts = _targets({"big.test": 5000})
    a, _ = apply_target_host_cap(ts, cap=2000, seed=SEED)
    b, _ = apply_target_host_cap(ts, cap=2000, seed=SEED)
    assert [t.endpoint for t in a] == [t.endpoint for t in b]


def test_different_seed_selects_differently():
    ts = _targets({"big.test": 5000})
    a, _ = apply_target_host_cap(ts, cap=2000, seed=SEED)
    c, _ = apply_target_host_cap(ts, cap=2000, seed=SEED + 1)
    assert [t.endpoint for t in a] != [t.endpoint for t in c]


def test_every_host_survives_the_cap():
    """上限不能让任何 host 整个消失 —— 那会让该 host 无法回权。"""
    ts = _targets({f"h{i}.test": 3000 for i in range(5)})
    keep, _ = apply_target_host_cap(ts, cap=10, seed=SEED)
    assert set(_hosts(keep)) == {f"h{i}.test" for i in range(5)}
    assert all(n == 10 for n in _hosts(keep).values())


@pytest.mark.parametrize("cap", [1, 2, 999999])
def test_cap_never_exceeds_limit(cap):
    ts = _targets({"a.test": 500, "b.test": 500})
    keep, _ = apply_target_host_cap(ts, cap=cap, seed=SEED)
    assert all(n <= cap for n in _hosts(keep).values())
