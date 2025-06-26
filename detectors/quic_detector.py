# detectors/quic_detector.py

import dpkt
from typing import Dict, Any

def _quic_draft_version(version: int) -> int:
    """
    模拟Wireshark的quic_draft_version函数，判断版本号是否有效。
    返回一个代表草案版本的数字，或0表示未知。
   
    """
    if (version >> 8) == 0xff0000: return version & 0xff  # IETF Drafts like 0xff00001d (29)
    if version == 0x00000001: return 34  # QUIC v1 Final
    if version == 0x6b3343cf: return 100 # QUIC v2
    if (version & 0x0F0F0F0F) == 0x0a0a0a0a: return 34 # GREASE versions
    # 其他特定厂商或旧草案版本可以按需添加
    return 0

def is_quic_packet(payload: bytes, sport: int, dport: int) -> bool:
    """
    一个IETF QUIC协议的启发式识别函数。
    当前仅实现了对Long Header的识别，因为Short Header识别需要状态。
    """
    # 检查点: Long Header的最小合理长度
    if len(payload) < 13:
        return False

    flags = payload[0]

    # 检查点: 必须是Long Header (第一个字节的MSB为1)
    if (flags & 0x80) == 0:
        # 这是Short Header。由于框架是无状态的，我们无法在不看到
        # Long Header的情况下验证它。因此，跳过Short Header。
        return False

    try:
        # 检查点: 版本号必须是已知的QUIC版本
        version = dpkt.struct.unpack_from('!I', payload, 1)[0]
        if _quic_draft_version(version) < 11: # 基于分析文档，检查版本是否 >= draft-11
            return False

        # 检查点: DCIL (Dest CID Len) 必须有效
        dcil = payload[5]
        if dcil > 20: # QUIC_MAX_CID_LENGTH
            return False

        # 检查点: 载荷长度是否足以容纳SCIL
        scil_offset = 6 + dcil
        if len(payload) <= scil_offset:
            return False

        # 检查点: SCIL (Src CID Len) 必须有效
        scil = payload[scil_offset]
        if scil > 20: # QUIC_MAX_CID_LENGTH
            return False
            
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, IndexError):
        return False
        
    return True

def register() -> Dict[str, Any]:
    """向主程序注册IETF QUIC识别器。"""
    return {
        "name": "QUIC",
        "function": is_quic_packet,
        "subscriptions": {
            "port_based": [
                {"protocol": "UDP", "port": 443}
            ]
        }
    }