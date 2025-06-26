# detectors/gquic_detector.py

import dpkt
from typing import Dict, Any

def is_gquic_packet(payload: bytes, sport: int, dport: int) -> bool:
    """
    一个GQUIC协议的启发式识别函数。
    它检查UDP载荷是否符合早期GQUIC或Q046的头部格式。
    """
    if len(payload) < 1:
        return False

    flags = payload[0]

    # 分支1: 早期GQUIC版本 (如 <= Q043)
    if (flags & 0x80) == 0 and (flags & 0x40) == 0:
        # 检查点: 长度至少13字节 (1 Flags + 8 CID + 4 Version)
        if len(payload) < 13:
            return False

        # 检查点: VRSN位(0x01)和CID位(0x08)必须为1
        if (flags & 0x01) == 0 or (flags & 0x08) == 0:
            return False
        
        try:
            # 检查点: 版本号前3字节是否为"Q02", "Q03", "Q04"
            version_prefix = dpkt.struct.unpack_from('!I', b'\x00' + payload[9:12])[0] # 模拟 ntoh24
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            return False
        
        # GQUIC_MAGIC2/3/4
        known_magics = {0x513032, 0x513033, 0x513034}
        return version_prefix in known_magics

    # 分支2: GQUIC Q046 Long Header
    elif (flags & 0x40) and (flags & 0x80):
        # 检查点: 长度至少14字节 (1 Flags + 4 Version + 1 CILs + 8 DCID)
        if len(payload) < 14:
            return False

        try:
            # 检查点: 版本号是否为"Q046" (0x51303436)
            version = dpkt.struct.unpack_from('!I', payload, 1)[0]
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            return False

        return version == 0x51303436 # GQUIC_VERSION_Q046

    return False

def register() -> Dict[str, Any]:
    """向主程序注册GQUIC识别器。"""
    return {
        "name": "GQUIC",
        "function": is_gquic_packet,
        "subscriptions": {
            "port_based": [
                {"protocol": "UDP", "port": 443},
                {"protocol": "UDP", "port": 80}
            ]
        }
    }