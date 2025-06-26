# detectors/dns_detector.py (已修复压缩指针解析漏洞)

import struct
import ipaddress
from typing import Dict, List, Any, Optional, Tuple, Set

# --- DNS 定义映射表 (保持不变) ---
RCODE_MAP = {0: "No error", 1: "Format error", 2: "Server failure", 3: "No such name", 4: "Not implemented", 5: "Refused"}
OPCODE_MAP = {0: "Standard query", 1: "Inverse query", 2: "Server status request", 4: "Notify", 5: "Update"}
RR_TYPE_MAP = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 52: "TLSA", 257: "CAA"}
CLASS_MAP = {1: "IN", 255: "ANY"}
DNSSEC_ALGO_MAP = {5: "RSA/SHA1", 7: "RSA/SHA1-NSEC3-SHA1", 8: "RSA/SHA-256", 10: "RSA/SHA-512", 13: "ECDSA P-256 with SHA-256", 14: "ECDSA P-384 with SHA-384"}
DS_DIGEST_MAP = {1: "SHA-1", 2: "SHA-256", 4: "SHA-384"}

# --- 协议识别逻辑 (保持不变) ---
def is_dns_packet(payload: bytes, sport: int, dport: int) -> bool:
    if len(payload) < 12: return False
    try:
        flags, qd, an, _, _ = struct.unpack('!HHHHH', payload[2:12])
        if (flags & 0x7800) != 0 or (qd + an) == 0: return False
    except struct.error: return False
    return True

# --- 字段解析逻辑 (关键修改) ---
def _expand_dns_name(payload: bytes, offset: int, recursion_guard: Set[int]) -> Tuple[Optional[str], int]:
    """
    健壮的DNS域名解析函数，增加了边界检查和压缩循环检测。
    :param payload: DNS报文载荷
    :param offset: 当前解析的起始偏移
    :param recursion_guard: 用于存储已访问过的指针偏移量，防止循环
    :return: 解析后的域名字符串和消耗的字节数
    """
    labels, orig_offset, consumed = [], offset, 0
    
    while offset < len(payload):
        if offset in recursion_guard: # 检测到压缩循环
            return None, 0
        recursion_guard.add(offset)

        length = payload[offset]
        offset += 1

        if length == 0:
            if not consumed: consumed = offset - orig_offset
            break
        
        if (length & 0xC0) == 0xC0:
            # 修正1: 增加边界检查，防止IndexError
            if offset >= len(payload):
                return None, 0 # 指针不完整
            
            ptr_offset = ((length & 0x3F) << 8) + payload[offset]
            
            # 修正2: 递归前传递守卫集，并且检查目标偏移是否已访问
            if ptr_offset in recursion_guard:
                return None, 0 # 检测到压缩循环
            
            # 创建一个新的守卫集合副本用于递归，以避免不同分支的干扰
            sub_recursion_guard = recursion_guard.copy()
            sub_recursion_guard.add(ptr_offset)
            
            sub_name, _ = _expand_dns_name(payload, ptr_offset, sub_recursion_guard)
            if sub_name is None: return None, 0
            
            labels.append(sub_name)
            if not consumed: consumed = offset + 1 - orig_offset
            offset += 1
            break
        else:
            if offset + length > len(payload): return None, 0 # 标签长度超限
            labels.append(payload[offset:offset+length].decode('latin-1', errors='ignore'))
            offset += length
            
    return ".".join(labels) if labels else "<Root>", consumed

# ... 其余函数保持不变 ...
def _format_type_bitmap(data: bytes) -> List[str]:
    # ... (代码与之前版本相同)
    types, offset = [], 0
    while offset < len(data):
        win_num, bmap_len = data[offset], data[offset+1]; offset += 2
        for i, byte in enumerate(data[offset:offset+bmap_len]):
            for j in range(8):
                if (byte >> (7-j)) & 1:
                    type_val = win_num * 256 + i * 8 + j
                    types.append(f"{RR_TYPE_MAP.get(type_val, 'Unknown')} ({type_val})")
        offset += bmap_len
    return types

def parse_dns_packet(payload: bytes) -> Optional[Dict[str, Any]]:
    parsed_data: Dict[str, Any] = {}; offset = 0
    if len(payload) > 2 and struct.unpack('!H', payload[:2])[0] == len(payload) - 2: offset = 2
    if len(payload) - offset < 12: return None
    tid, flags, qd, an, ns, ar = struct.unpack('!HHHHHH', payload[offset:offset+12]); offset += 12
    
    op_val = (flags >> 11) & 0xF
    rc_val = flags & 0xF
    parsed_data['header'] = {
        "transaction_id": hex(tid),
        "is_response": bool(flags & 0x8000),
        "opcode": f"{OPCODE_MAP.get(op_val, 'Unknown')} ({op_val})",
        "is_authoritative": bool(flags & 0x0400), "is_truncated": bool(flags & 0x0200),
        "recursion_desired": bool(flags & 0x0100), "recursion_available": bool(flags & 0x0080),
        "response_code": f"{RCODE_MAP.get(rc_val, 'Unknown')} ({rc_val})",
        "counts": {"questions": qd, "answers": an, "authorities": ns, "additionals": ar}
    }
    
    parsed_data['questions'] = []
    for _ in range(qd):
        # 每次调用都传入一个新的空集合作为递归守卫
        qname, c = _expand_dns_name(payload, offset, set())
        if qname is None: break # 解析失败则中止
        offset += c
        if offset + 4 > len(payload): break
        qtype, qclass = struct.unpack('!HH', payload[offset:offset+4]); offset += 4
        parsed_data['questions'].append({"name": qname, "type": f"{RR_TYPE_MAP.get(qtype, 'Unknown')} ({qtype})", "class": f"{CLASS_MAP.get(qclass, 'Unknown')} ({qclass})"})

    for sec_name, count in [("answers", an), ("authorities", ns), ("additionals", ar)]:
        parsed_data[sec_name] = []
        for _ in range(count):
            if offset >= len(payload): break
            # 每次调用都传入一个新的空集合作为递归守卫
            rr_name, c = _expand_dns_name(payload, offset, set())
            if rr_name is None: break # 解析失败则中止
            offset += c
            if offset + 10 > len(payload): break
            # ... 后续解析逻辑不变 ...
            rr_type_val, rr_class_val, ttl, rdlen = struct.unpack('!HHIH', payload[offset:offset+10]); offset += 10
            rdata_offset, rdata_bytes = offset, payload[offset:offset+rdlen]
            
            type_str = f"{RR_TYPE_MAP.get(rr_type_val, 'Unknown')} ({rr_type_val})"
            class_str = f"{CLASS_MAP.get(rr_class_val, 'Unknown')} ({rr_class_val})"
            current_rr: Dict[str, Any] = {"name": rr_name, "type": type_str, "class": class_str, "ttl": ttl}
            rdata = {}
            
            if rr_type_val == 1 and len(rdata_bytes) == 4: rdata['address'] = str(ipaddress.IPv4Address(rdata_bytes))
            elif rr_type_val == 28 and len(rdata_bytes) == 16: rdata['address'] = str(ipaddress.IPv6Address(rdata_bytes))
            elif rr_type_val in [2, 5, 12]:
                rdata['domain_name'], _ = _expand_dns_name(payload, rdata_offset, set())
            elif rr_type_val == 46 and len(rdata_bytes) > 17:
                tc, alg, lbl, ottl, exp, inc, kt = struct.unpack('!HBI!IIH', rdata_bytes[:17])
                signer, c_signer = _expand_dns_name(payload, rdata_offset+17, set())
                rdata = {
                    'type_covered': f"{RR_TYPE_MAP.get(tc, 'Unknown')} ({tc})",
                    'algorithm': f"{DNSSEC_ALGO_MAP.get(alg, 'Unknown')} ({alg})",
                    'labels': lbl, 'original_ttl': ottl, 'signature_expiration': exp,
                    'signature_inception': inc, 'key_tag': kt, 'signer_name': signer,
                    'signature': rdata_bytes[17+c_signer:].hex()
                }
            else: rdata['raw_data'] = rdata_bytes.hex()
            
            current_rr['data'] = rdata
            parsed_data[sec_name].append(current_rr)
            offset += rdlen
            
    return parsed_data

def register() -> Dict[str, Any]:
    return {"name": "DNS", "function": is_dns_packet, "parser_function": parse_dns_packet, "subscriptions": {"port_based": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}]}}