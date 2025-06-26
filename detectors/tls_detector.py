# detectors/tls_detector.py (功能增强和修复版)

import struct
from typing import Dict, Any, List, Optional

# --- 【增强】全面的TLS定义映射表 (基于 packet-tls-utils.c 及 IANA 标准) ---

CONTENT_TYPES = {
    20: "Change Cipher Spec", 21: "Alert", 22: "Handshake", 23: "Application Data", 24: "Heartbeat"
}
HANDSHAKE_TYPES = {
    0: "Hello Request", 1: "Client Hello", 2: "Server Hello", 4: "New Session Ticket",
    8: "Encrypted Extensions", 11: "Certificate", 12: "Server Key Exchange",
    13: "Certificate Request", 14: "Server Hello Done", 15: "Certificate Verify",
    16: "Client Key Exchange", 20: "Finished"
}
# 【修复】字典键已从字符串改为整数
VERSIONS = {
    0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"
}
# 【增强】扩充密码套件列表
CIPHER_SUITES = {
    0x000a: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", 0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA", 0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384", 0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384", 0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xc009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", 0xc00a: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xc023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", 0xc024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    0xc027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", 0xc028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0x5600: "TLS_FALLBACK_SCSV", 0x00ff: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"
}
# 【增强】扩充扩展列表
EXTENSIONS = {
    0: "server_name", 5: "status_request", 10: "supported_groups", 11: "ec_point_formats",
    13: "signature_algorithms", 16: "application_layer_protocol_negotiation",
    17: "status_request_v2", 18: "signed_certificate_timestamp", 21: "padding",
    23: "extended_master_secret", 35: "session_ticket", 41: "pre_shared_key",
    42: "supported_versions", 43: "cookie", 44: "psk_key_exchange_modes", 45: "key_share",
    51: "post_handshake_auth", 13172: "next_protocol_negotiation", 65281: "renegotiation_info"
}
# 【增强】扩充加密组列表
SUPPORTED_GROUPS = {
    23: "secp256r1", 24: "secp384r1", 25: "secp521r1", 29: "x25519", 30: "x448",
    256: "ffdhe2048", 257: "ffdhe3072", 258: "ffdhe4096"
}
# 【增强】扩充签名算法列表
SIGNATURE_ALGORITHMS = {
    0x0401: "rsa_pkcs1_sha256", 0x0501: "rsa_pkcs1_sha384", 0x0601: "rsa_pkcs1_sha512",
    0x0804: "rsa_pss_rsae_sha256", 0x0805: "rsa_pss_rsae_sha384", 0x0806: "rsa_pss_rsae_sha512",
    0x0403: "ecdsa_secp256r1_sha256", 0x0503: "ecdsa_secp384r1_sha384", 0x0603: "ecdsa_secp521r1_sha512"
}
EC_POINT_FORMATS = {0: "uncompressed", 1: "ansiX962_compressed_prime", 2: "ansiX962_compressed_char2"}


# --- 协议识别逻辑 ---
def is_tls_packet(payload: bytes, sport: int, dport: int) -> bool:
    if len(payload) < 5: return False
    ct = payload[0]
    if ct not in CONTENT_TYPES: return False
    try:
        ver = struct.unpack('!H', payload[1:3])[0]
        if not (0x0300 <= ver <= 0x0304): return False
        record_len = struct.unpack('!H', payload[3:5])[0]
        if len(payload) < 5 + record_len: return False
    except struct.error:
        return False
    return True

# --- 【增强】扩展解析辅助函数 ---
def _parse_sni(content: bytes) -> Dict:
    if len(content) < 5: return {'error': 'Invalid SNI data'}
    list_len = struct.unpack('!H', content[0:2])[0]
    if list_len != len(content) - 2: return {'error': 'Invalid SNI list length'}
    name_type = content[2]
    if name_type == 0: # host_name
        name_len = struct.unpack('!H', content[3:5])[0]
        if name_len != len(content) - 5: return {'error': 'Invalid host_name length'}
        return {'host_name': content[5:].decode('utf-8', 'ignore')}
    return {'error': 'Unknown name type'}

def _parse_supported_groups(content: bytes) -> Dict:
    if len(content) < 2: return {'error': 'Invalid supported_groups data'}
    list_len = struct.unpack('!H', content[0:2])[0]
    if list_len != len(content) - 2 or list_len % 2 != 0:
        return {'error': 'Invalid groups list length'}
    groups = []
    for i in range(2, len(content), 2):
        group_id = struct.unpack('!H', content[i:i+2])[0]
        groups.append(SUPPORTED_GROUPS.get(group_id, f"Unknown_Group_0x{group_id:04x}"))
    return {'supported_groups': groups}

def _parse_signature_algorithms(content: bytes) -> Dict:
    if len(content) < 2: return {'error': 'Invalid signature_algorithms data'}
    list_len = struct.unpack('!H', content[0:2])[0]
    if list_len != len(content) - 2 or list_len % 2 != 0:
        return {'error': 'Invalid algorithms list length'}
    algos = []
    for i in range(2, len(content), 2):
        algo_id = struct.unpack('!H', content[i:i+2])[0]
        algos.append(SIGNATURE_ALGORITHMS.get(algo_id, f"Unknown_Algo_0x{algo_id:04x}"))
    return {'signature_algorithms': algos}

def _parse_alpn(content: bytes) -> Dict:
    if len(content) < 2: return {'error': 'Invalid ALPN data'}
    list_len = struct.unpack('!H', content[0:2])[0]
    if list_len != len(content) - 2: return {'error': 'Invalid ALPN list length'}
    protocols, offset = [], 2
    while offset < len(content):
        proto_len = content[offset]; offset += 1
        if offset + proto_len > len(content): break
        protocols.append(content[offset:offset+proto_len].decode('utf-8', 'ignore'))
        offset += proto_len
    return {'protocols': protocols}

def _parse_supported_versions(content: bytes) -> Dict:
    if len(content) < 1: return {'error': 'Invalid supported_versions data'}
    list_len = content[0]
    if list_len != len(content) - 1 or list_len % 2 != 0:
        return {'error': 'Invalid versions list length'}
    versions = []
    for i in range(1, len(content), 2):
        ver_id = struct.unpack('!H', content[i:i+2])[0]
        versions.append(VERSIONS.get(ver_id, f"Unknown_Version_0x{ver_id:04x}"))
    return {'supported_versions': versions}

# --- 【增强】主解析逻辑 ---
def _parse_extensions(ext_data: bytes) -> Dict[str, Any]:
    extensions, offset = {}, 0
    while offset + 4 <= len(ext_data):
        ext_type_val, ext_len = struct.unpack('!HH', ext_data[offset:offset+4]); offset += 4
        if offset + ext_len > len(ext_data): break
        ext_content = ext_data[offset:offset+ext_len]
        ext_name = EXTENSIONS.get(ext_type_val, f"unknown_extension_{ext_type_val}")
        
        parsed_data = {}
        if ext_name == "server_name":
            parsed_data = _parse_sni(ext_content)
        elif ext_name == "supported_groups":
            parsed_data = _parse_supported_groups(ext_content)
        elif ext_name == "signature_algorithms":
            parsed_data = _parse_signature_algorithms(ext_content)
        elif ext_name == "application_layer_protocol_negotiation":
            parsed_data = _parse_alpn(ext_content)
        elif ext_name == "supported_versions":
            parsed_data = _parse_supported_versions(ext_content)
        else:
            parsed_data = {'data': ext_content.hex()} # 对未特殊处理的扩展，显示原始数据
        
        extensions[ext_name] = parsed_data
        offset += ext_len
    return extensions

def _parse_handshake_message(msg_type: int, msg_data: bytes) -> Dict[str, Any]:
    if msg_type != 1: # 目前只详细解析Client Hello
        return {'data': msg_data.hex()}
    
    if len(msg_data) < 38: return {'parsing_error': 'Incomplete Client Hello'}
    data, offset = {}, 0
    
    ver_val = struct.unpack('!H', msg_data[offset:offset+2])[0]; offset += 2
    # 【修复】直接用整数键查找
    data['version'] = f"{VERSIONS.get(ver_val, 'Unknown')} (0x{ver_val:04x})"
    
    data['random'] = msg_data[offset:offset+32].hex(); offset += 32
    
    sid_len = msg_data[offset]; offset += 1
    data['session_id'] = msg_data[offset:offset+sid_len].hex(); offset += sid_len
    
    if offset + 2 > len(msg_data): return {'client_hello': data}
    cs_len = struct.unpack('!H', msg_data[offset:offset+2])[0]; offset += 2
    if offset + cs_len > len(msg_data): return {'client_hello': data}
    cipher_suites = []
    for i in range(0, cs_len, 2):
        cs_val = struct.unpack('!H', msg_data[offset+i:offset+i+2])[0]
        cipher_suites.append(f"{CIPHER_SUITES.get(cs_val, 'Unknown')} (0x{cs_val:04x})")
    data['cipher_suites'] = cipher_suites; offset += cs_len
    
    if offset + 1 > len(msg_data): return {'client_hello': data}
    cm_len = msg_data[offset]; offset += 1
    if offset + cm_len > len(msg_data): return {'client_hello': data}
    data['compression_methods'] = [c for c in msg_data[offset:offset+cm_len]]; offset += cm_len
    
    if offset + 2 <= len(msg_data):
        ext_len = struct.unpack('!H', msg_data[offset:offset+2])[0]; offset += 2
        if offset + ext_len <= len(msg_data):
            data['extensions'] = _parse_extensions(msg_data[offset:offset+ext_len])
    
    return {'client_hello': data}

def parse_tls_packet(payload: bytes) -> Optional[Dict[str, Any]]:
    if not is_tls_packet(payload, 0, 0): return None
    all_records, offset = [], 0
    while offset + 5 <= len(payload):
        ct_val, ver_val, length = payload[offset], struct.unpack('!H',payload[offset+1:offset+3])[0], struct.unpack('!H',payload[offset+3:offset+5])[0]
        if offset + 5 + length > len(payload): break
        record_payload = payload[offset+5 : offset+5+length]
        
        # 【修复】直接用整数键查找
        version_str = f"{VERSIONS.get(ver_val, 'Unknown')} (0x{ver_val:04x})"
        ctype_str = f"{CONTENT_TYPES.get(ct_val, 'Unknown')} ({ct_val})"
        current_record: Dict[str, Any] = {"content_type": ctype_str, "version": version_str, "length": length}
        
        if ct_val == 22: # Handshake
            messages, msg_offset = [], 0
            while msg_offset + 4 <= len(record_payload):
                msg_type_val, msg_len = record_payload[msg_offset], struct.unpack('!I', b'\x00' + record_payload[msg_offset+1:msg_offset+4])[0]
                if msg_offset + 4 + msg_len > len(record_payload): break
                msg_data = record_payload[msg_offset+4 : msg_offset+4+msg_len]
                h_type_str = f"{HANDSHAKE_TYPES.get(msg_type_val, 'Unknown')} ({msg_type_val})"
                parsed_msg: Dict[str, Any] = {"type": h_type_str, "length": msg_len, **_parse_handshake_message(msg_type_val, msg_data)}
                messages.append(parsed_msg); msg_offset += 4 + msg_len
            current_record['handshake_protocol'] = messages
        
        all_records.append(current_record)
        offset += 5 + length
    return {"records": all_records} if all_records else None

def register() -> Dict[str, Any]:
    return {"name": "TLS", "function": is_tls_packet, "parser_function": parse_tls_packet, "subscriptions": {"port_based": [{"protocol": "TCP", "port": 443}]}}