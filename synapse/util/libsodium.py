import hashlib
from nacl.encoding import HexEncoder
from nacl.signing import VerifyKey

# 用于dweb-browser的签名验证
def SignVerify(msg, signature, publicKey) -> bool:
    bmsg = msg.encode()
    bsignature = signature.encode()
    bpublicKey = publicKey.encode()

    sha256_hash = hashlib.sha256()
    sha256_hash.update(bmsg)

    verify_key = VerifyKey(bpublicKey, encoder=HexEncoder)

    try:
        verify_key.verify(sha256_hash.hexdigest(), HexEncoder.decode(bsignature), encoder=HexEncoder)
    except Exception as e:
        return False

    return True