"""ERC-8004 registered-identity liveness scanner."""

__version__ = "0.1.0"

# 走操作系统证书库。企业网络或本地代理做 TLS 拦截时，certifi 内置包不含拦截方的
# 根证书，httpx 会一律 CERTIFICATE_VERIFY_FAILED。inject 之后仍然是【正常校验】，
# 只是信任源换成系统钥匙串 —— 不降低安全性，不要改成 verify=False。
import ssl as _ssl

# inject_into_ssl 会把 ssl.SSLContext 整个类替换掉，连显式构造的实例也会被接管，
# 而且注入后再去构造「注入前保存的类」会无限递归。
#
# 探测器需要一个【真正不校验】的 context：证书过期/自签/域名不匹配的服务【是活着的】，
# 判成死的就错了，所以要能不校验地再连一次做分类。
# 解法是在注入【之前】就把这个 context 实例造好，全程复用（SSLContext 本就可复用）。
UNVERIFIED_SSL_CONTEXT = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
UNVERIFIED_SSL_CONTEXT.check_hostname = False
UNVERIFIED_SSL_CONTEXT.verify_mode = _ssl.CERT_NONE

try:  # pragma: no cover
    import truststore

    truststore.inject_into_ssl()
except ImportError:  # pragma: no cover
    pass
