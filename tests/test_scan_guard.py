"""日志扫描的两道防线：金丝雀覆盖范围 + 「0 条日志」不变量。

这是本仓第二次栽在同一类失败上：**端点不报错、静默返回空**，
扫描「成功」完成并产出一份空的数据集。

第一次：rpc.flashbots.net 对历史区间返回 []，87% 的以太坊扫描是空的。
第二次：scroll 报 0 条日志。原因是金丝雀只从链头往回找 12 × max_log_range，
        max_log_range 调到 50,000 后也才 60 万个区块，而 scroll 的注册活动
        停在离链头 230 万个区块之前 → 找不到金丝雀 → 端点校验【整个被跳过】。
        重扫同一区间得到 470 条。

所以金丝雀必须覆盖整个待扫区间；并且即使金丝雀这条路失效，
「链上有 token 却一条日志都没有」也必须直接报错。
"""

import asyncio

import pytest

from e8004.abi import topic0
from e8004.stages.s02_logs import _find_canary_block, _token_zero_exists

T0 = topic0("Registered(uint256,string,address)")
IDENT = "0x8004a169fb4a3325136eb29fa0ceb6d2e539a432"


class FakeRpc:
    """只在 [lo, hi] 这个老区间里有日志的假端点。"""

    def __init__(self, log_lo: int, log_hi: int):
        self.log_lo, self.log_hi = log_lo, log_hi
        self.calls = 0

    async def call(self, method, params):
        self.calls += 1
        if method == "eth_getLogs":
            f = int(params[0]["fromBlock"], 16)
            t = int(params[0]["toBlock"], 16)
            if f <= self.log_hi and t >= self.log_lo:
                blk = max(f, self.log_lo)
                return [{"blockNumber": hex(blk)}]
            return []
        raise AssertionError(method)


def test_canary_finds_activity_far_from_head():
    """scroll 的实际形态：注册活动结束在离链头 230 万个区块之前。"""
    head, start = 34_620_385, 28_736_393
    rpc = FakeRpc(29_500_000, 30_300_000)     # 老区间，离 head 很远
    got = asyncio.run(_find_canary_block(rpc, IDENT, head, 50_000, start))
    assert got is not None, f"应当找到金丝雀（探了 {rpc.calls} 次）"
    assert 29_500_000 <= got <= 30_300_000


def test_canary_search_stays_within_scan_range():
    """不能探到 start 之前去 —— 那不是本次要扫的区间。"""
    head, start = 1_000_000, 900_000
    rpc = FakeRpc(0, 100)                      # 日志远在 start 之前
    assert asyncio.run(_find_canary_block(rpc, IDENT, head, 1_000, start)) is None


def test_canary_probe_count_is_bounded():
    """金丝雀是开扫前的额外开销，不能失控。"""
    rpc = FakeRpc(-2, -1)                      # 永远没有日志
    asyncio.run(_find_canary_block(rpc, IDENT, 50_000_000, 50_000, 0, probes=24))
    assert rpc.calls <= 24, rpc.calls


class OwnerOfRpc:
    def __init__(self, result):
        self.result = result

    async def call(self, method, params):
        if self.result is None:
            raise RuntimeError("execution reverted")
        return self.result


@pytest.mark.parametrize("ret,expected", [
    ("0x" + "00" * 12 + "aa" * 20, True),      # 有 owner → token 存在
    ("0x" + "00" * 32, False),                 # 零地址 → 不存在
    ("0x", False),
    (None, False),                             # revert → 不存在
])
def test_token_zero_exists(ret, expected):
    assert asyncio.run(_token_zero_exists(OwnerOfRpc(ret), IDENT)) is expected


# ------------------------------------------------------- HTTP 400 = 范围过大

def test_http_400_on_getlogs_is_treated_as_range_error():
    """celo 的公共 RPC 在窗口内日志太多时返 HTTP 400，不是 JSON-RPC range 错误码。

    不把它归成范围错误的话，折半逻辑不会触发，客户端只会换端点重试，
    两个端点都 400 之后整条链崩溃 —— 实测 celo 的 9,766 个 agent 因此全部丢失。
    """
    from e8004.rpc import RpcError

    err = RpcError(-32000, "HTTP 400: block range too large", "eth_getLogs")
    assert err.is_range_error is True


def test_genuine_client_errors_are_not_range_errors():
    """别把所有 400 都当范围问题，否则真正的参数错误会被折半掩盖成死循环。"""
    from e8004.rpc import RpcError

    assert RpcError(-32602, "invalid argument 0", "eth_getLogs").is_range_error is False
    assert RpcError(-32601, "method not found", "eth_getLogs").is_range_error is False


# --------------------------------------------- batch 上限：自适应而不是崩溃

@pytest.mark.parametrize("msg,code,expected", [
    ('{"code": -32014, "message": "maximum 10 calls in 1 batch"}', -32014, True),
    ("batch size limit exceeded", -32000, True),
    ("too many requests in batch", -32000, True),
    ("block range is too large", -32000, False),      # 别和范围错误混淆
    ("execution reverted", -32000, False),
])
def test_batch_too_large_detection(msg, code, expected):
    """各家 RPC 的 batch 上限不同且不公布，只能按报错文本认。

    实测 mainnet.base.org 只允许 10 个调用，超了返 -32014，
    原来会让整条链的扫描崩掉（base 因此全军覆没一次）。
    """
    from e8004.rpc import RpcError

    assert RpcError(code, msg, "batch").is_batch_too_large is expected


# ------------------------------- 金丝雀失效时必须 fail closed，不能默默继续

class CanaryRpc:
    """没有任何 Registered 日志的端点；ownerOf(0) 是否返回持有者可控。"""

    def __init__(self, has_token: bool):
        self.has_token = has_token

    async def call(self, method, params):
        if method == "eth_getLogs":
            return []                      # 永远找不到金丝雀
        if method == "eth_call":
            if not self.has_token:
                raise RuntimeError("execution reverted")
            return "0x" + "00" * 12 + "aa" * 20
        raise AssertionError(method)


def test_no_canary_but_token_exists_must_raise():
    """校验器自身失效 ≠ 校验通过。

    scroll 就是这么丢的：金丝雀探测够不到它的注册活动区间，端点校验被【整个
    跳过】，一个静默返空的端点畅通无阻，最后报告「✓ 0 条日志」。
    把探测窗口调多调宽只提高命中概率，堵不住这个漏 —— 必须改默认行为。
    """
    rpc = CanaryRpc(has_token=True)
    assert asyncio.run(_token_zero_exists(rpc, IDENT)) is True
    # 有 token 却一个金丝雀都找不到 → scan_chain 必须拒绝扫描
    assert asyncio.run(_find_canary_block(rpc, IDENT, 1_000_000, 10_000, 0)) is None


def test_no_canary_and_no_token_is_legitimately_empty():
    """该注册表上本来就没有 token 时，0 条日志是真的，不该报错。"""
    rpc = CanaryRpc(has_token=False)
    assert asyncio.run(_token_zero_exists(rpc, IDENT)) is False
    assert asyncio.run(_find_canary_block(rpc, IDENT, 1_000_000, 10_000, 0)) is None
