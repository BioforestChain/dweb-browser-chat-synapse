import hashlib
from nacl.encoding import HexEncoder
from nacl.signing import VerifyKey

# 用于dweb-browser的签名验证
def SignVerify(msg, signature, publicKey) -> bool:
    sha256_hash = hashlib.sha256()
    sha256_hash.update(msg)

    verify_key = VerifyKey(publicKey, encoder=HexEncoder)

    try:
        verify_key.verify(sha256_hash.hexdigest(), HexEncoder.decode(signature), encoder=HexEncoder)
    except Exception as e:
        return False

    return True