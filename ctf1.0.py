#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CTF网络流量取证分析系统 - 战场级装备 v5.0
核心战场优化：
1. 全协议覆盖：ICMP/DNS隧道检测与解码
2. 自适应解密：Base64自定义字符表自动探测与暴力破解
3. 零依赖解析：纯Python pcapng解析器，单文件可运行
"""

import os
os.environ["http_proxy"] = "http://127.0.0.1:7897"
os.environ["https_proxy"] = "http://127.0.0.1:7897"
import sys
import struct
import json
import re
import hashlib
import logging
import tempfile
import mmap
import base64
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any, Set, Iterator, Union
from datetime import datetime
from enum import IntEnum
import math

# 尝试导入加密库，如果失败则使用备用实现
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    import google.genai as genai
    GEMINI_AVAILABLE = True
    USE_NEW_API = True
except ImportError:
    try:
        import google.generativeai as genai
        from google.generativeai.types import GenerationConfig
        GEMINI_AVAILABLE = True
        USE_NEW_API = False
        # 已弃用的google.generativeai包，建议升级到google.genai
    except ImportError:
        GEMINI_AVAILABLE = False
        USE_NEW_API = False

# ================= 配置区 =================
GENI_API_KEY = "AIzaSyD1dAx1vnofzrktYqAdcchvEsFgU4TpNCg" 
MAX_MEMORY_MB = 1024       # 调大内存限制，防止分块丢失数据
ENABLE_KEY_BRUTEFORCE = False  # 必须保持 False，否则会再次卡死在 #1561
KEY_BRUTEFORCE_TIMEOUT = 30

# 代理配置（自动检测或手动设置）
USE_PROXY = True
PROXY_HOST = "127.0.0.1"  # 代理主机
PROXY_PORT = 7897        # 代理端口
PROXY_TYPE = "http"      # http 或 socks5

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ctf_battle_v5.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)
class PcapNGBlockType(IntEnum):
    """PCAPNG Block类型"""
    INTERFACE_DESCRIPTION = 0x00000001
    PACKET = 0x00000002
    SIMPLE_PACKET = 0x00000003
    NAME_RESOLUTION = 0x00000004
    INTERFACE_STATISTICS = 0x00000005
    ENHANCED_PACKET = 0x00000006
    SECTION_HEADER = 0x0A0D0D0A


class PurePcapParser:
    """纯Python PCAP/PCAPNG解析器，零外部依赖"""
    
    # 链路类型映射
    LINKTYPE_ETHERNET = 1
    LINKTYPE_RAW = 101
    LINKTYPE_LINUX_SLL = 113
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.is_pcapng = False
        self.little_endian = True
        self.interfaces = []  # 接口信息列表
        self.current_interface = 0
        
    def parse(self) -> Iterator[Tuple[float, bytes, int]]:
        """
        解析pcap/pcapng文件，生成器返回 (timestamp, packet_data, pkt_num)
        支持：
        - 标准PCAP
        - PCAPNG (Section Header Block, Interface Description Block, Enhanced Packet Block等)
        """
        with open(self.file_path, 'rb') as f:
            # 内存映射大文件
            try:
                mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                use_mmap = True
            except:
                mm = f
                use_mmap = False
            
            # 检测文件类型
            magic = mm.read(4)
            mm.seek(0)
            
            if magic == b'\x0a\x0d\x0d\x0a':
                # PCAPNG格式
                self.is_pcapng = True
                yield from self._parse_pcapng(mm)
            elif magic in (b'\xa1\xb2\xc3\xd4', b'\xd4\xc3\xb2\xa1'):
                # 标准PCAP
                yield from self._parse_pcap(mm)
            else:
                raise ValueError(f"未知的PCAP魔数: {magic.hex()}")
            
            if use_mmap:
                mm.close()
    
    def _parse_pcapng(self, mm) -> Iterator[Tuple[float, bytes, int]]:
        """解析PCAPNG格式"""
        pkt_num = 0
        
        while True:
            # 读取Block头部
            block_type_data = mm.read(4)
            if len(block_type_data) < 4:
                break  # 文件结束
            
            block_type = struct.unpack('<I', block_type_data)[0]
            
            # 读取Block长度
            block_len_data = mm.read(4)
            if len(block_len_data) < 4:
                break
            block_len = struct.unpack('<I', block_len_data)[0]
            
            # 读取Block内容
            block_body_len = block_len - 12  # 减去type(4)+len(4)+trailing_len(4)
            if block_body_len < 0:
                break
            
            block_body = mm.read(block_body_len)
            mm.read(4)  # 跳过trailing length
            
            # 处理不同类型的Block
            if block_type == PcapNGBlockType.SECTION_HEADER:
                self._parse_section_header(block_body)
            elif block_type == PcapNGBlockType.INTERFACE_DESCRIPTION:
                self._parse_interface_description(block_body)
            elif block_type == PcapNGBlockType.ENHANCED_PACKET:
                ts, pkt_data = self._parse_enhanced_packet(block_body)
                if pkt_data:
                    pkt_num += 1
                    yield (ts, pkt_data, pkt_num)
            elif block_type == PcapNGBlockType.SIMPLE_PACKET:
                pkt_data = self._parse_simple_packet(block_body)
                if pkt_data:
                    pkt_num += 1
                    yield (0.0, pkt_data, pkt_num)  # Simple Packet无时间戳
            elif block_type == PcapNGBlockType.PACKET:
                ts, pkt_data = self._parse_packet_block(block_body)
                if pkt_data:
                    pkt_num += 1
                    yield (ts, pkt_data, pkt_num)
    
    def _parse_section_header(self, data: bytes):
        """解析Section Header Block"""
        if len(data) < 16:
            return
        
        # Byte-Order Magic
        bom = struct.unpack('<I', data[8:12])[0]
        self.little_endian = (bom == 0x1A2B3C4D)
        logger.info(f"PCAPNG字节序: {'小端' if self.little_endian else '大端'}")
    
    def _parse_interface_description(self, data: bytes):
        """解析Interface Description Block"""
        if len(data) < 8:
            return
        
        fmt = '<I' if self.little_endian else '>I'
        link_type = struct.unpack(fmt, data[0:4])[0]
        snap_len = struct.unpack(fmt, data[4:8])[0]
        
        self.interfaces.append({
            'link_type': link_type,
            'snap_len': snap_len
        })
        logger.debug(f"发现接口: LinkType={link_type}, SnapLen={snap_len}")
    
    def _parse_enhanced_packet(self, data: bytes) -> Tuple[float, bytes]:
        """解析Enhanced Packet Block"""
        if len(data) < 20:
            return 0.0, b''
        
        fmt = '<I' if self.little_endian else '>I'
        interface_id = struct.unpack(fmt, data[0:4])[0]
        ts_high = struct.unpack(fmt, data[4:8])[0]
        ts_low = struct.unpack(fmt, data[8:12])[0]
        cap_len = struct.unpack(fmt, data[12:16])[0]
        orig_len = struct.unpack(fmt, data[16:20])[0]
        
        # 计算时间戳（微秒精度）
        ts = (ts_high << 32 | ts_low) / 1e6
        
        # 提取数据包（跳过20字节头部）
        pkt_data = data[20:20+cap_len]
        
        # 处理链路层
        return ts, self._strip_link_layer(pkt_data, interface_id)
    
    def _parse_simple_packet(self, data: bytes) -> bytes:
        """解析Simple Packet Block"""
        if len(data) < 4:
            return b''
        
        fmt = '<I' if self.little_endian else '>I'
        orig_len = struct.unpack(fmt, data[0:4])[0]
        return data[4:4+orig_len]
    
    def _parse_packet_block(self, data: bytes) -> Tuple[float, bytes]:
        """解析Packet Block (旧版PCAPNG)"""
        if len(data) < 16:
            return 0.0, b''
        
        fmt = '<I' if self.little_endian else '>I'
        interface_id = struct.unpack(fmt, data[0:4])[0]
        drops_count = struct.unpack(fmt, data[4:8])[0]
        ts_high = struct.unpack(fmt, data[8:12])[0]
        ts_low = struct.unpack(fmt, data[12:16])[0]
        cap_len = struct.unpack(fmt, data[16:20])[0]
        
        ts = (ts_high << 32 | ts_low) / 1e6
        pkt_data = data[20:20+cap_len]
        
        return ts, self._strip_link_layer(pkt_data, interface_id)
    
    def _strip_link_layer(self, pkt_data: bytes, interface_id: int) -> bytes:
        """去除链路层头部，返回IP层数据"""
        if interface_id >= len(self.interfaces):
            return pkt_data
        
        link_type = self.interfaces[interface_id].get('link_type', self.LINKTYPE_ETHERNET)
        
        if link_type == self.LINKTYPE_ETHERNET:
            if len(pkt_data) < 14:
                return pkt_data
            # 检查是否为IP (0x0800) 或 IPv6 (0x86DD)
            eth_type = struct.unpack('>H', pkt_data[12:14])[0]
            if eth_type == 0x0800:  # IPv4
                return pkt_data[14:]
            elif eth_type == 0x86DD:  # IPv6
                return pkt_data[14:]
            else:
                return pkt_data[14:]
        elif link_type == self.LINKTYPE_RAW:
            return pkt_data
        elif link_type == self.LINKTYPE_LINUX_SLL:
            if len(pkt_data) < 16:
                return pkt_data
            return pkt_data[16:]
        
        return pkt_data
    
    def _parse_pcap(self, mm) -> Iterator[Tuple[float, bytes, int]]:
        """解析标准PCAP格式"""
        # 读取全局头部
        global_header = mm.read(24)
        if len(global_header) < 24:
            return
        
        magic = global_header[0:4]
        if magic == b'\xa1\xb2\xc3\xd4':
            endian = '>'
        else:
            endian = '<'
        
        link_type = struct.unpack(endian + 'I', global_header[20:24])[0]
        self.interfaces.append({'link_type': link_type})
        
        pkt_num = 0
        while True:
            # 读取包头部
            pkt_header = mm.read(16)
            if len(pkt_header) < 16:
                break
            
            ts_sec = struct.unpack(endian + 'I', pkt_header[0:4])[0]
            ts_usec = struct.unpack(endian + 'I', pkt_header[4:8])[0]
            incl_len = struct.unpack(endian + 'I', pkt_header[8:12])[0]
            orig_len = struct.unpack(endian + 'I', pkt_header[12:16])[0]
            
            # 读取包数据
            pkt_data = mm.read(incl_len)
            if len(pkt_data) < incl_len:
                break
            
            ts = ts_sec + ts_usec / 1e6
            pkt_num += 1
            
            # 去除链路层
            ip_data = self._strip_link_layer(pkt_data, 0)
            yield (ts, ip_data, pkt_num)


# ========== ICMP隧道检测器 ==========
class ICMPTunnelDetector:
    """ICMP隧道检测与解码"""
    
    # ICMP类型
    ICMP_ECHO_REQUEST = 8
    ICMP_ECHO_REPLY = 0
    
    def __init__(self):
        self.sessions = defaultdict(list)  # (src,dst) -> [(seq, payload, ts)]
        self.detected_tunnels = []
    
    def analyze_packet(self, ts: float, src_ip: str, dst_ip: str, icmp_data: bytes) -> Optional[Dict]:
        """
        分析ICMP包，检测隧道特征
        返回隧道证据或None
        """
        if len(icmp_data) < 8:
            return None
        
        icmp_type = icmp_data[0]
        icmp_code = icmp_data[1]
        checksum = struct.unpack('>H', icmp_data[2:4])[0]
        
        # 提取payload（跳过8字节头部）
        payload = icmp_data[8:]
        
        # 记录所有ICMP流量用于调试
        logger.debug(f"ICMP: {src_ip}->{dst_ip} type={icmp_type} payload_size={len(payload)}")
        
        # 检测特征1: Payload过大（正常ping通常32-64字节）
        # 放宽阈值，8字节以上也认为有隧道可能
        if len(payload) > 8:
            # 检测特征2: Payload包含可打印字符比例异常
            printable_ratio = sum(1 for b in payload if 32 <= b <= 126) / len(payload)
            
            # 检测特征3: 熵值分析（加密数据vs随机数据）
            entropy = self._calculate_entropy(payload)
            
            # 检测特征4: 是否为重复模式（隧道通常有结构）
            is_tunnel = False
            tunnel_type = "Unknown"
            
            if printable_ratio > 0.7 and entropy > 4.5:
                # 高可打印字符+高熵 = 可能是Base64编码的隧道
                is_tunnel = True
                tunnel_type = "Likely_Base64_Encoded"
            elif printable_ratio < 0.3 and entropy > 7.0:
                # 低可打印+极高熵 = 可能是加密隧道
                is_tunnel = True
                tunnel_type = "Likely_Encrypted"
            
            if is_tunnel:
                # 尝试解码
                decoded = self._try_decode_payload(payload)
                
                session_key = (src_ip, dst_ip)
                self.sessions[session_key].append({
                    'seq': len(self.sessions[session_key]),
                    'payload': payload,
                    'ts': ts,
                    'decoded': decoded
                })
                
                return {
                    'type': 'ICMP_Tunnel',
                    'tunnel_type': tunnel_type,
                    'src': src_ip,
                    'dst': dst_ip,
                    'payload_size': len(payload),
                    'entropy': entropy,
                    'printable_ratio': printable_ratio,
                    'decoded': decoded[:200] if decoded else None,
                    'raw_snippet': payload[:50].hex()
                }
        
        return None
    
    def _calculate_entropy(self, data: bytes) -> float:
        """计算香农熵（优化版，使用Counter提高效率）"""
        if not data:
            return 0.0
        
        # 使用Counter统计字节频率
        freq = Counter(data)
        entropy = 0.0
        data_len = len(data)
        
        for count in freq.values():
            p_x = count / data_len
            entropy -= p_x * math.log2(p_x)
        
        return entropy
    
    def _try_decode_payload(self, payload: bytes) -> Optional[bytes]:
        """尝试解码ICMP Payload"""
        # 尝试标准Base64
        try:
            return base64.b64decode(payload)
        except:
            pass
        
        # 尝试URL-safe Base64
        try:
            return base64.urlsafe_b64decode(payload)
        except:
            pass
        
        # 尝试自定义字符表（通过频率分析推测）
        custom_decoded = self._try_custom_base64(payload)
        if custom_decoded:
            return custom_decoded
        
        return None
    
    def _try_custom_base64(self, payload: bytes) -> Optional[bytes]:
        """尝试使用频率分析推测自定义Base64字符表"""
        # 统计字符频率
        freq = Counter(payload.decode('latin-1', errors='ignore'))
        most_common = [c for c, _ in freq.most_common(64)]
        
        if len(most_common) < 64:
            return None
        
        # 构建可能的字符表映射（标准Base64变体）
        std_b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        
        # 尝试映射并解码
        try:
            trans_table = str.maketrans(''.join(most_common), std_b64)
            translated = payload.decode('latin-1').translate(trans_table)
            return base64.b64decode(translated)
        except:
            return None
    
    def get_reassembled_stream(self, src_ip: str, dst_ip: str) -> bytes:
        """重组特定方向的ICMP隧道流"""
        session = self.sessions.get((src_ip, dst_ip), [])
        return b''.join([s['payload'] for s in sorted(session, key=lambda x: x['seq'])])


# ========== DNS隧道检测器 ==========
class DNSTunnelDetector:
    """DNS隧道检测与解码"""
    
    # 常见DNS隧道工具特征
    TUNNEL_TOOLS = {
        'iodine': {
            'record_types': ['NULL', 'TXT', 'SRV', 'MX', 'CNAME', 'A'],
            'encoding': 'Base128',  # 自定义编码
            'upstream': 'NULL',  # 上行使用NULL记录
            'downstream': 'NULL',  # 下行使用NULL记录
            'check_interval': 4,  # 默认检查间隔4秒
        },
        'dnscat2': {
            'record_types': ['TXT', 'CNAME', 'MX', 'A', 'AAAA'],
            'encoding': 'Hex/Base32',
            'encryption': 'RC4',
            'session_id': 2,  # 2字节会话ID
        },
        'dns2tcp': {
            'record_types': ['TXT', 'A'],
            'encoding': 'Base32',
        },
        'CobaltStrike': {
            'record_types': ['A'],
            'pattern': r'[a-z0-9]{16}\.[\w\-]+\.\w+',  # 16字符随机前缀
            'beacon_interval': 60,  # 默认60秒心跳
        }
    }
    
    def __init__(self):
        self.queries = defaultdict(list)  # domain -> [query_data]
        self.suspicious_domains = set()
        self.detected_tunnels = []
    
    def analyze_query(self, ts: float, src_ip: str, dst_ip: str, 
                      query_name: str, query_type: int) -> Optional[Dict]:
        """
        分析DNS查询，检测隧道特征
        """
        # 标准化查询名
        query_name = query_name.lower().strip('.')
        
        # 记录所有DNS查询用于调试
        logger.debug(f"DNS: {src_ip}->{dst_ip} query={query_name} type={query_type}")
        
        # 特征1: 查询名长度
        name_len = len(query_name)
        if name_len > 30:  # 正常查询通常<30字符
            # 特征2: 熵值分析
            entropy = self._calculate_entropy(query_name)
            
            # 特征3: 子域名深度
            labels = query_name.split('.')
            depth = len(labels)
            
            # 特征4: 编码检测
            encoding_type = self._detect_encoding(labels[0] if labels else '')
            
            # 特征5: 记录类型异常
            record_type = self._get_record_type_name(query_type)
            is_suspicious_type = record_type in ['TXT', 'NULL', 'SRV', 'MX']
            
            # 综合评分
            score = 0
            indicators = []
            
            if name_len > 100:
                score += 2
                indicators.append("超长域名")
            if entropy > 3.8:
                score += 3
                indicators.append("高熵值")
            if depth > 4:
                score += 1
                indicators.append("深子域名")
            if encoding_type != 'Plain':
                score += 2
                indicators.append(f"{encoding_type}编码")
            if is_suspicious_type:
                score += 2
                indicators.append(f"可疑记录类型{record_type}")
            
            # 尝试解码子域名
            decoded = self._try_decode_subdomain(labels[0]) if labels else None
            
            if score >= 5:
                self.suspicious_domains.add(query_name)
                
                # 识别可能的工具
                tool_guess = self._guess_tool(query_name, record_type, encoding_type)
                
                return {
                    'type': 'DNS_Tunnel_Suspicious',
                    'src': src_ip,
                    'dst': dst_ip,
                    'query': query_name,
                    'record_type': record_type,
                    'score': score,
                    'indicators': indicators,
                    'entropy': round(entropy, 2),
                    'encoding_guess': encoding_type,
                    'decoded_payload': decoded[:100] if decoded else None,
                    'likely_tool': tool_guess
                }
        
        return None
    
    def _calculate_entropy(self, s: str) -> float:
        """计算字符串熵值（优化版，使用Counter提高效率）"""
        if not s:
            return 0.0
        
        # 使用Counter统计字符频率
        freq = Counter(s)
        entropy = 0.0
        s_len = len(s)
        
        for count in freq.values():
            p_x = count / s_len
            entropy -= p_x * math.log2(p_x)
        
        return entropy
    
    def _detect_encoding(self, subdomain: str) -> str:
        """检测子域名编码类型"""
        # Base64特征: 包含A-Z, a-z, 0-9, +/, 可能以=结尾
        if re.match(r'^[A-Za-z0-9+/]+={0,2}$', subdomain) and len(subdomain) % 4 == 0:
            return 'Base64'
        
        # Base32特征: 大写+数字，2-7
        if re.match(r'^[A-Z2-7]+$', subdomain) and len(subdomain) % 8 == 0:
            return 'Base32'
        
        # Base16/Hex特征: 纯十六进制
        if re.match(r'^[a-f0-9]+$', subdomain, re.I) and len(subdomain) % 2 == 0:
            return 'Hex'
        
        # Base36: 数字+小写字母
        if re.match(r'^[a-z0-9]+$', subdomain) and len(subdomain) > 20:
            return 'Base36'
        
        # 自定义编码: 混合大小写+数字，无规律
        if len(subdomain) > 30 and re.match(r'^[a-zA-Z0-9]+$', subdomain):
            return 'Custom_Base64'
        
        return 'Plain'
    
    def _try_decode_subdomain(self, subdomain: str) -> Optional[bytes]:
        """尝试解码子域名"""
        encoding = self._detect_encoding(subdomain)
        
        try:
            if encoding == 'Base64':
                # 尝试标准Base64
                return base64.b64decode(subdomain + '==')
            elif encoding == 'Base32':
                return base64.b32decode(subdomain + '=======')
            elif encoding == 'Hex':
                return bytes.fromhex(subdomain)
            elif encoding == 'Custom_Base64':
                # 尝试自定义字符表
                return self._try_custom_decode(subdomain)
        except:
            pass
        
        return None
    
    def _try_custom_decode(self, data: str) -> Optional[bytes]:
        """尝试使用频率分析解码自定义Base64"""
        # 实现与ICMP检测器类似的逻辑
        freq = Counter(data)
        most_common = [c for c, _ in freq.most_common(64)]
        
        if len(most_common) < 64:
            return None
        
        std_b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        try:
            trans_table = str.maketrans(''.join(most_common), std_b64)
            translated = data.translate(trans_table)
            return base64.b64decode(translated + '==')
        except:
            return None
    
    def _get_record_type_name(self, qtype: int) -> str:
        """获取记录类型名称"""
        types = {
            1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR',
            15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 255: 'ANY',
            10: 'NULL'  # 实验性/私有类型，常被隧道使用
        }
        return types.get(qtype, f'TYPE{qtype}')
    
    def _guess_tool(self, query: str, record_type: str, encoding: str) -> str:
        """推测使用的隧道工具"""
        if record_type == 'NULL':
            return 'iodine (NULL记录特征)'
        if record_type == 'TXT' and encoding == 'Base64':
            return 'dnscat2 (TXT+Base64特征)'
        if record_type == 'A' and len(query.split('.')[0]) == 16:
            return 'CobaltStrike (16字符随机前缀)'
        if encoding == 'Base32':
            return 'dns2tcp (Base32特征)'
        return 'Unknown'


# ========== 自适应Base64解码器 ==========
class AdaptiveBase64Decoder:
    """自适应Base64解码器，支持自定义字符表"""
    
    # 标准Base64字符表
    STANDARD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    URLSAFE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    
    # 常见自定义字符表（来自已知工具）
    KNOWN_ALPHABETS = {
        'rfc4648': "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        'rfc4648_urlsafe': "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
        'base64url': "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
        'iodine': "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",  # 标准
        'dnscat2': "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_",  # 变体
    }
    
    def __init__(self):
        self.detected_alphabet = None
    
    def decode(self, data: Union[str, bytes], hint: Optional[str] = None) -> Optional[bytes]:
        """
        智能解码，自动检测字符表
        """
        if isinstance(data, bytes):
            text = data.decode('latin-1', errors='ignore')
        else:
            text = data
        
        # 清理数据
        text = text.strip()
        
        # 如果提供了提示，直接使用
        if hint and hint in self.KNOWN_ALPHABETS:
            return self._decode_with_alphabet(text, self.KNOWN_ALPHABETS[hint])
        
        # 尝试标准解码
        try:
            return base64.b64decode(text)
        except:
            pass
        
        # 尝试URL-safe
        try:
            return base64.urlsafe_b64decode(text)
        except:
            pass
        
        # 自动检测字符表
        alphabet = self._detect_alphabet(text)
        if alphabet:
            return self._decode_with_alphabet(text, alphabet)
        
        return None
    
    def _detect_alphabet(self, data: str) -> Optional[str]:
        """通过频率分析检测字符表"""
        # 统计字符分布
        freq = Counter(c for c in data if c.isalnum() or c in '+/=-_')
        
        # 如果字符分布符合标准Base64特征
        has_upper = sum(1 for c in freq if c.isupper()) > 10
        has_lower = sum(1 for c in freq if c.islower()) > 10
        has_digit = sum(1 for c in freq if c.isdigit()) > 5
        
        if has_upper and has_lower and has_digit:
            # 可能是标准Base64变体
            # 尝试通过末尾字符判断
            if data.endswith('-') or data.endswith('_'):
                return self.URLSAFE_ALPHABET
            return self.STANDARD_ALPHABET
        
        # 如果只有小写+数字，可能是自定义
        if not has_upper and has_lower and has_digit:
            # 构建自定义字符表（按频率排序）
            sorted_chars = [c for c, _ in freq.most_common(64)]
            if len(sorted_chars) >= 64:
                return ''.join(sorted_chars)
        
        return None
    
    def _decode_with_alphabet(self, data: str, alphabet: str) -> Optional[bytes]:
        """使用指定字符表解码"""
        # 构建反向映射
        std_alphabet = self.STANDARD_ALPHABET
        
        if len(alphabet) != 64:
            return None
        
        try:
            # 创建转换表
            trans = str.maketrans(alphabet, std_alphabet)
            translated = data.translate(trans)
            return base64.b64decode(translated + '==')
        except:
            return None
    
    def brute_force_decode(self, data: str, expected_patterns: List[bytes]) -> Optional[Tuple[str, bytes]]:
        """
        暴力破解字符表
        expected_patterns: 期望在解码结果中出现的特征（如b'whoami', b'<?php'等）
        """
        # 从数据中提取使用的字符
        unique_chars = list(set(c for c in data if c.isalnum() or c in '+/=-_'))
        
        if len(unique_chars) < 64:
            return None
        
        # 尝试常见排列组合（简化版，实际可用更高效的算法）
        from itertools import permutations
        
        # 限制尝试次数，避免爆炸
        max_attempts = 1000
        attempts = 0
        
        # 基于频率的启发式排序
        freq = Counter(data)
        sorted_chars = [c for c, _ in freq.most_common(64)]
        
        # 尝试标准映射
        for variant in [sorted_chars, sorted(sorted_chars), unique_chars[:64]]:
            if attempts >= max_attempts:
                break
            
            alphabet = ''.join(variant[:64])
            try:
                decoded = self._decode_with_alphabet(data, alphabet)
                if decoded:
                    # 验证是否包含期望模式
                    for pattern in expected_patterns:
                        if pattern in decoded:
                            return (alphabet, decoded)
            except:
                pass
            
            attempts += 1
        
        return None


# ========== 集成分析引擎 ==========
@dataclass
class Evidence:
    """取证证据数据类"""
    type: str
    src: str
    dst: str
    details: dict
    timestamp: float
    confidence: float = 1.0
    packet_num: int = 0

class BattleForensicsEngine:
    """战场级取证引擎，集成多种协议分析"""
    
    def __init__(self, pcap_path: str):
        """初始化引擎
        
        Args:
            pcap_path: PCAP文件路径
        """
        self.pcap_path = pcap_path
        self.parser = PurePcapParser(pcap_path)
        self.icmp_detector = ICMPTunnelDetector()
        self.dns_detector = DNSTunnelDetector()
        self.base64_decoder = AdaptiveBase64Decoder()
        self.evidence_chain = []
        
        # 传统TCP分析
        self.tcp_streams = defaultdict(list)
        self.syn_counts = Counter()
        
    def analyze(self) -> Iterator[Evidence]:
        """主分析流程 - 已移除导致卡死的大包记录逻辑"""
        logger.info(f"开始战场级分析: {self.pcap_path}")
        print(f"[*] 开始分析文件: {self.pcap_path}")
        
        pkt_count = 0
        protocol_stats = Counter()
        
        for ts, pkt_data, pkt_num in self.parser.parse():
            pkt_count += 1
            if pkt_count % 10000 == 0:
                print(f"[*] 已处理 {pkt_count} 个包...")
            
            # 统计协议分布（仅取一个字节，速度极快）
            if len(pkt_data) >= 10:
                protocol = pkt_data[9]
                protocol_stats[protocol] += 1
            
            # 核心分析逻辑
            try:
                ev = self._analyze_packet(ts, pkt_data, pkt_num)
                if ev:
                    self.evidence_chain.append(ev)
                    yield ev
            except Exception:
                continue
        
        print(f"[+] 分析完成，共 {pkt_count} 个包")
    
    def _analyze_packet(self, ts, pkt_data, pkt_num):
        """
        增强型协议分析：关键字分类筐 + 强化 ICMP 隧道检测
        异常流量直接分类而不是笼统的 KEYWORD_MATCH
        """
        if len(pkt_data) < 34: return None
        
        # --- 关键字分类筐：每个关键字对应一个专属分类 ---
        keywords = {
            b"shell.php": "WEBSHELL_PATH",
            b"eval(": "WEBSHELL_EXEC",
            b"system(": "WEBSHELL_EXEC",
            b"base64_decode": "ENCODING_DETECTED",
            b"alphabet": "CUSTOM_BASE64_TABLE",
            b"POST /": "HTTP_POST_REQUEST",
            b"key=": "PARAM_KEY_FOUND",
            b"config": "CONFIG_ACCESS",
            b"flag{": "FLAG_DETECTED",
            b"passwd": "PASSWD_ACCESS",
            b"shadow": "SHADOW_ACCESS",
            b"mysql": "DB_ACCESS",
            b"nc -e": "REVERSE_SHELL",
            b"dnscat": "DNS_TUNNEL_TOOL",
            b"iodine": "DNS_TUNNEL_TOOL",
            b"ptunnel": "ICMP_TUNNEL_TOOL"
        }
        
        # 先检查关键字，命中后直接分类
        for kw, kw_type in keywords.items():
            if kw in pkt_data:
                return Evidence(
                    type=kw_type,
                    src="Attacker",
                    dst="Victim",
                    details={"match": kw.decode(errors='ignore'), "hex": pkt_data[:200].hex()},
                    timestamp=ts,
                    packet_num=pkt_num,
                    confidence=0.95
                )
        
        # --- 强化 ICMP 隧道检测（只要 >64 字节就强制标记） ---
        for offset in [14, 16]:
            try:
                if len(pkt_data) > offset + 20 and (pkt_data[offset] & 0xF0) == 0x40:
                    protocol = pkt_data[offset + 9]
                    src_ip = ".".join(map(str, pkt_data[offset+12:offset+16]))
                    dst_ip = ".".join(map(str, pkt_data[offset+16:offset+20]))
                    
                    # ICMP (协议号 1) 隧道强制检测
                    if protocol == 1:
                        icmp_payload = pkt_data[offset + 28:]
                        if len(icmp_payload) > 64:  # 降低阈值到 64 字节
                            return Evidence(
                                type="ICMP_TUNNEL",
                                src=src_ip,
                                dst=dst_ip,
                                details={
                                    "size": len(icmp_payload),
                                    "payload_hex": icmp_payload[:128].hex(),
                                    "protocol": protocol
                                },
                                timestamp=ts,
                                packet_num=pkt_num,
                                confidence=0.85
                            )
                    
                    # TCP (协议号 6) 继续分析
                    if protocol == 6:
                        tcp_data = pkt_data[offset + 20:]
                        res = self._analyze_tcp(ts, src_ip, dst_ip, tcp_data, pkt_num)
                        if res:
                            return res
                    
                    break
            except:
                pass
        
        return None
    
    def _analyze_tcp(self, ts: float, src_ip: str, dst_ip: str, 
                     tcp_data: bytes, pkt_num: int) -> Optional[Evidence]:
        """TCP分析（简化版，重点在隧道检测）"""
        src_port = struct.unpack('>H', tcp_data[0:2])[0]
        dst_port = struct.unpack('>H', tcp_data[2:4])[0]
        flags = tcp_data[13]
        
        payload = tcp_data[20:] if len(tcp_data) > 20 else b''
        
        # SYN扫描检测
        if (flags & 0x02) and not (flags & 0x10):  # SYN无ACK
            self.syn_counts[dst_ip] += 1
            # 降低阈值，只要有任意一个SYN包就认为是扫描
            if self.syn_counts[dst_ip] >= 1:
                return Evidence(
                    type="PortScan",
                    src=src_ip,
                    dst=dst_ip,
                    details={"scanned_ports": self.syn_counts[dst_ip]},
                    timestamp=ts,
                    confidence=0.9,
                    packet_num=pkt_num
                )
        
        # HTTP/Webshell检测
        if payload and b"HTTP/" in payload[:100]:
            return self._analyze_http(ts, src_ip, dst_ip, src_port, dst_port, payload, pkt_num)
        
        return None
    
    def _analyze_http(self, ts, src_ip, dst_ip, src_port, dst_port, payload, pkt_num):
        """极简版HTTP分析：彻底解决大数据包卡死问题"""
        try:
            # 仅检测前200字节，避免处理整个大Payload
            header_part = payload[:200]
            
            # 只要是 POST 请求或者访问了敏感后缀，就记录为证据
            if b"POST" in header_part or b".php" in header_part:
                path = "未知路径"
                match = re.search(rb'(?:GET|POST) ([^\s]+) HTTP', header_part)
                if match:
                    path = match.group(1).decode('latin-1', errors='ignore')
                
                return Evidence(
                    type="HTTP_ACTIVITY",
                    src=src_ip,
                    dst=dst_ip,
                    details={"path": path, "method": "POST" if b"POST" in header_part else "GET"},
                    timestamp=ts,
                    packet_num=pkt_num
                )
        except:
            pass
        return None
    
    def _analyze_udp(self, ts: float, src_ip: str, dst_ip: str, 
                     udp_data: bytes, pkt_num: int) -> Optional[Evidence]:
        """UDP分析（DNS检测）"""
        src_port = struct.unpack('>H', udp_data[0:2])[0]
        dst_port = struct.unpack('>H', udp_data[2:4])[0]
        udp_len = struct.unpack('>H', udp_data[4:6])[0]
        
        payload = udp_data[8:]
        
        # DNS检测 (port 53)
        if src_port == 53 or dst_port == 53:
            try:
                dns_result = self._parse_dns(payload)
                if dns_result:
                    query_name = dns_result.get('qname', '')
                    query_type = dns_result.get('qtype', 0)
                    
                    # DNS隧道检测
                    tunnel_ev = self.dns_detector.analyze_query(
                        ts, src_ip, dst_ip, query_name, query_type
                    )
                    
                    if tunnel_ev:
                        return Evidence(
                            type="DNS_Tunnel",
                            src=src_ip,
                            dst=dst_ip,
                            details=tunnel_ev,
                            timestamp=ts,
                            confidence=tunnel_ev.get('score', 5) / 10,
                            packet_num=pkt_num
                        )
            except:
                pass
        
        return None
    
    def _parse_dns(self, data: bytes) -> Optional[Dict]:
        """简化DNS解析"""
        if len(data) < 12:
            return None
        
        transaction_id = struct.unpack('>H', data[0:2])[0]
        flags = struct.unpack('>H', data[2:4])[0]
        questions = struct.unpack('>H', data[4:6])[0]
        
        offset = 12
        
        # 解析查询名
        labels = []
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if length & 0xC0:  # 压缩指针
                offset += 2
                break
            offset += 1
            labels.append(data[offset:offset+length].decode('latin-1', errors='ignore'))
            offset += length
        
        qname = '.'.join(labels)
        
        # 查询类型和类
        if offset + 4 <= len(data):
            qtype = struct.unpack('>H', data[offset:offset+2])[0]
            qclass = struct.unpack('>H', data[offset+2:offset+4])[0]
            return {'qname': qname, 'qtype': qtype, 'qclass': qclass}
        
        return None
    
    def _analyze_icmp(self, ts: float, src_ip: str, dst_ip: str, 
                      icmp_data: bytes, pkt_num: int) -> Optional[Evidence]:
        """ICMP隧道检测"""
        tunnel_ev = self.icmp_detector.analyze_packet(ts, src_ip, dst_ip, icmp_data)
        
        if tunnel_ev:
            return Evidence(
                type="ICMP_Tunnel",
                src=src_ip,
                dst=dst_ip,
                details=tunnel_ev,
                timestamp=ts,
                confidence=0.85,
                packet_num=pkt_num
            )
        
        return None
    
    def get_icmp_reassembled(self, src: str, dst: str) -> bytes:
        """获取重组的ICMP流"""
        return self.icmp_detector.get_reassembled_stream(src, dst)


# ========== AI分析专家 ==========
class BattleAIExpert:
    """战场级AI专家"""
    
    def __init__(self):
        if GEMINI_AVAILABLE and GENI_API_KEY:
            # 自动配置代理（如果启用）
            if USE_PROXY:
                proxy_url = f"{PROXY_TYPE}://{PROXY_HOST}:{PROXY_PORT}"
                os.environ['HTTP_PROXY'] = proxy_url
                os.environ['HTTPS_PROXY'] = proxy_url
                print(f"[*] 已配置代理: {proxy_url}")
            
            genai.configure(api_key=GENI_API_KEY)
            self.model = genai.GenerativeModel(
                model_name='models/gemini-2.5-flash',
                system_instruction="""你是战场级CTF取证专家，擅长处理：
1. ICMP/DNS隧道流量分析
2. 自定义Base64字符表解密
3. 多协议混合攻击场景

规则：
- 对于隧道流量，指出具体工具和编码方式
- 对于自定义加密，给出字符表和解密结果
- 答案必须精确，附带证据包号"""
            )
            self.use_ai = True
        else:
            self.use_ai = False
    
    def analyze(self, evidence_list: List[Evidence], questions: List[str], pcap_path: str = None) -> Dict:
        """批量分析，支持传入PCAP路径以便提取原始流量进行AI分析"""
        if not self.use_ai:
            return self._local_analysis(evidence_list, questions)
        
        # 提取流量汇总（可选）
        traffic_summary = None
        if pcap_path:
            traffic_summary = self._extract_traffic_summary(pcap_path)
        
        # 构建报告
        report = self._build_battle_report(evidence_list)
        
        # 根据是否有流量汇总构建不同的prompt
        if traffic_summary:
            # 有原始流量汇总的情况
            prompt = f"""你是一个经验丰富的CTF取证专家，擅长分析网络流量。

基于以下原始流量汇总和自动检测出的证据，综合回答问题。

=== 原始流量汇总 ===
{traffic_summary}

=== 自动检测证据 ===
{json.dumps(report, ensure_ascii=False, indent=2)[:80000]}

=== 题目 ===
{chr(10).join([f"{i+1}. {q}" for i, q in enumerate(questions)])}

注意：对于每个问题，给出最高程度的肯定并附带相关证据。
输出JSON：{{"answers": [{{"question": "...", "answer": "...", "confidence": 0.95, "technique": "..."}}]}}"""
        else:
            # 纯依赖检测证据的情况
            prompt = f"""基于战场取证证据回答问题：

=== 证据 ===
{json.dumps(report, ensure_ascii=False, indent=2)[:80000]}

=== 题目 ===
{chr(10).join([f"{i+1}. {q}" for i, q in enumerate(questions)])}

输出JSON：{{"answers": [{{"question": "...", "answer": "...", "evidence_pkt": 123, "technique": "..."}}]}}"""
        
        print("[调试] prompt 前500字符:\n", prompt[:500])  # 添加这行
        
        # 尝试联网调用AI，设定超时时间防止无限卡死
        timeout_seconds = 30
        result_text = None
        try:
            # 运行在子线程以支持超时控制
            import threading, queue, time
            q = queue.Queue()
            def worker():
                try:
                    if USE_NEW_API:
                        resp = self.model.generate_content(
                            prompt,
                            generation_config={"response_mime_type": "application/json", "temperature": 0.1}
                        )
                    else:
                        resp = self.model.generate_content(
                            prompt,
                            generation_config=GenerationConfig(
                                response_mime_type="application/json",
                                temperature=0.1
                            )
                        )
                    q.put(resp.text)
                except Exception as e:
                    q.put(e)
            thread = threading.Thread(target=worker)
            thread.daemon = True
            thread.start()
            start_time = time.time()
            thread.join(timeout_seconds)
            if thread.is_alive():
                raise TimeoutError(f"AI请求超过 {timeout_seconds}s 超时")
            result_text = q.get()
            if isinstance(result_text, Exception):
                raise result_text
            elapsed = time.time() - start_time
            print(f"[*] AI调用完成，用时 {elapsed:.1f}s")
            print("[调试] AI返回原始文本:\n", result_text)  # 添加这行
            return json.loads(result_text)
        except TimeoutError as te:
            print(f"[!] {te}, 回退到本地规则分析")
            return self._local_analysis(evidence_list, questions)
        except Exception as e:
            print(f"[!] AI调用出错: {e}, 使用本地规则")
            logger.error(f"AI失败: {e}")
            return self._local_analysis(evidence_list, questions)
    
    def _extract_traffic_summary(self, pcap_path: str) -> str:
        """从PCAP文件提取原始流量汇总（统计+样本）"""
        try:
            parser = PurePcapParser(pcap_path)
            
            # 统计变量
            protocol_count = Counter()  # 协议分布
            long_dns_queries = []  # 长域名查询
            icmp_payloads = []  # ICMP Payload样本
            tcp_streams_map = defaultdict(list)  # TCP流
            unique_ips = set()  # 唯一IP对
            port_scans = Counter()  # 扫描目标
            http_posts = []  # HTTP POST请求
            tls_handshakes = []  # TLS握手
            
            pkt_num = 0
            
            for ts, pkt_data, pkt_id in parser.parse():
                pkt_num += 1
                if pkt_num > 50000:  # 限制处理包数，避免太大的PCAP卡死
                    break
                
                if len(pkt_data) < 20:
                    continue
                
                # 解析IP层
                version_ihl = pkt_data[0]
                version = version_ihl >> 4
                
                if version == 4:
                    # IPv4处理
                    ihl = (version_ihl & 0x0F) * 4
                    if len(pkt_data) < ihl + 8:
                        continue
                    
                    protocol = pkt_data[9]
                    src_ip = ".".join(map(str, pkt_data[12:16]))
                    dst_ip = ".".join(map(str, pkt_data[16:20]))
                    payload = pkt_data[ihl:]
                    
                elif version == 6:
                    # IPv6处理 - 固定40字节头部
                    if len(pkt_data) < 40:
                        continue
                    
                    protocol = pkt_data[6]  # Next Header字段
                    src_ip = self._format_ipv6_address(pkt_data[8:24])
                    dst_ip = self._format_ipv6_address(pkt_data[24:40])
                    payload = pkt_data[40:]
                    
                else:
                    print(f"[调试] 包 {pkt_num}: 非IPv4/6，版本={version}")
                    continue
                
                unique_ips.add((src_ip, dst_ip))
                protocol_count[protocol] += 1
                
                # TCP处理
                if protocol == 6 and len(payload) >= 20:
                    src_port = struct.unpack('>H', payload[0:2])[0]
                    dst_port = struct.unpack('>H', payload[2:4])[0]
                    flags = payload[13]
                    
                    # SYN扫描检测
                    if (flags & 0x02) and not (flags & 0x10):
                        port_scans[dst_ip] += 1
                    
                    tcp_payload = payload[20:] if len(payload) > 20 else b''
                    if tcp_payload:
                        tcp_streams_map[f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"].append(len(tcp_payload))
                    
                    # HTTP POST检测
                    if tcp_payload and b"POST" in tcp_payload[:100]:
                        try:
                            header_part = tcp_payload[:200]
                            path_match = re.search(rb'POST ([^\s]+) HTTP', header_part)
                            if path_match:
                                path = path_match.group(1).decode('latin-1', errors='ignore')
                                http_posts.append({
                                    'src': src_ip,
                                    'dst': dst_ip,
                                    'path': path[:100],
                                    'size': len(tcp_payload)
                                })
                        except:
                            pass
                    
                    # TLS握手检测 (端口443)
                    if dst_port == 443 and len(tcp_payload) >= 5:
                        if tcp_payload[0] == 0x16:  # Handshake
                            tls_handshakes.append({
                                'src': src_ip,
                                'dst': dst_ip,
                                'type': 'handshake',
                                'size': len(tcp_payload)
                            })
                
                # UDP处理（DNS）
                elif protocol == 17 and len(payload) >= 8:
                    src_port = struct.unpack('>H', payload[0:2])[0]
                    dst_port = struct.unpack('>H', payload[2:4])[0]
                    udp_payload = payload[8:]
                    
                    # DNS解析（端口53）
                    if src_port == 53 or dst_port == 53:
                        try:
                            if len(udp_payload) >= 12:
                                offset = 12
                                labels = []
                                while offset < len(udp_payload):
                                    length = udp_payload[offset]
                                    if length == 0:
                                        break
                                    if length & 0xC0:
                                        break
                                    offset += 1
                                    labels.append(udp_payload[offset:offset+length].decode('latin-1', errors='ignore')[:30])
                                    offset += length
                                
                                query_name = '.'.join(labels)
                                if len(query_name) > 30:
                                    long_dns_queries.append((query_name, len(query_name)))
                        except:
                            pass
                
                # ICMP处理
                elif protocol in (1, 58) and len(payload) >= 8:
                    icmp_payload = payload[8:]
                    if len(icmp_payload) > 8:
                        # 只记录样本，避免数据过多
                        if len(icmp_payloads) < 10:
                            icmp_payloads.append({
                                'src': src_ip,
                                'dst': dst_ip,
                                'size': len(icmp_payload),
                                'entropy': self._quick_entropy(icmp_payload)
                            })
            
            # 构建摘要报告文本
            summary = f"""【原始流量分析摘要】

[文件处理统计]
- 总包数: {pkt_num}
- 唯一IP对: {len(unique_ips)}

[协议分布]
"""
            for proto, count in protocol_count.most_common():
                proto_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(proto, f'Other({proto})')
                summary += f"- {proto_name}: {count}个包\n"
            
            if long_dns_queries:
                summary += f"\n[可疑DNS查询（超长域名）] 共{len(long_dns_queries)}条\n"
                for query, qlen in sorted(long_dns_queries, key=lambda x: -x[1])[:5]:
                    summary += f"- {query[:80]} ({qlen}字符)\n"
            
            if port_scans:
                summary += f"\n[端口扫描检测] 被扫描目标\n"
                for target, count in port_scans.most_common(5):
                    summary += f"- {target}: {count}个SYN包\n"
            
            if http_posts:
                summary += f"\n[HTTP POST请求] 共{len(http_posts)}条\n"
                for post in http_posts[:3]:
                    summary += f"- {post['src']}->{post['dst']}: {post['path']} ({post['size']}字节)\n"
            
            if tls_handshakes:
                summary += f"\n[TLS握手] 共{len(tls_handshakes)}条\n"
                for tls in tls_handshakes[:3]:
                    summary += f"- {tls['src']}->{tls['dst']}: {tls['size']}字节\n"
            
            if icmp_payloads:
                summary += f"\n[ICMP隧道样本] 共{len(icmp_payloads)}条\n"
                for sample in icmp_payloads[:3]:
                    summary += f"- {sample['src']}->{sample['dst']}: {sample['size']}字节 熵={sample['entropy']:.2f}\n"
            
            # 控制长度，避免超出token限制
            if len(summary) > 10000:
                summary = summary[:9500] + "\n\n[内容过长，已截断...]"
            
            print("[调试] 流量汇总内容:\n", summary)   # 添加这行
            return summary
        except Exception as e:
            logger.error(f"流量汇总提取失败: {e}")
            return ""
    
    def _format_ipv6_address(self, addr_bytes: bytes) -> str:
        """格式化IPv6地址为标准表示"""
        if len(addr_bytes) != 16:
            return "invalid"
        
        # 将16字节转换为8个16位整数
        groups = []
        for i in range(0, 16, 2):
            group = struct.unpack('>H', addr_bytes[i:i+2])[0]
            groups.append(f"{group:04x}")
        
        # 压缩连续的0
        addr_str = ':'.join(groups)
        
        # 查找最长的0序列进行压缩
        import re
        # 替换最长的连续:0000:序列为::
        addr_str = re.sub(r'(:0000)+(?=:|$)', '::', addr_str)
        # 处理开头和结尾的特殊情况
        addr_str = re.sub(r'^::', '::', addr_str)
        addr_str = re.sub(r':::$', '::', addr_str)
        
        return addr_str
    
    def _quick_entropy(self, data: bytes) -> float:
        """快速计算熵值"""
        if len(data) < 2:
            return 0.0
        freq = Counter(data)
        entropy = 0.0
        for count in freq.values():
            p = count / len(data)
            entropy -= p * math.log2(p)
        return entropy
    
    def _build_battle_report(self, evidence_list: List[Evidence]) -> Dict:
        """构建战场报告"""
        tunnels = [e for e in evidence_list if 'Tunnel' in e.type]
        webshells = [e for e in evidence_list if 'Webshell' in e.type]
        scans = [e for e in evidence_list if 'Scan' in e.type]
        
        return {
            "tunnels": {
                "icmp": [e.details for e in tunnels if e.type == 'ICMP_Tunnel'],
                "dns": [e.details for e in tunnels if e.type == 'DNS_Tunnel']
            },
            "webshells": [e.details for e in webshells],
            "scans": [e.details for e in scans],
            "summary": {
                "total": len(evidence_list),
                "tunnels": len(tunnels),
                "webshells": len(webshells)
            }
        }
    
    def _local_analysis(self, evidence_list: List[Evidence], questions: List[str]) -> Dict:
        """本地规则分析（无AI时）"""
        answers = []
        
        for q in questions:
            q_lower = q.lower()
            answer = "未确定"
            pkt = 0
            
            # ICMP隧道相关
            if "icmp" in q_lower or "隧道" in q_lower:
                for ev in evidence_list:
                    if ev.type == 'ICMP_Tunnel':
                        answer = f"检测到ICMP隧道，类型: {ev.details.get('tunnel_type')}"
                        pkt = ev.packet_num
                        break
            
            # DNS隧道相关
            elif "dns" in q_lower:
                for ev in evidence_list:
                    if ev.type == 'DNS_Tunnel':
                        answer = f"检测到DNS隧道，工具推测: {ev.details.get('likely_tool')}"
                        pkt = ev.packet_num
                        break
            
            # 自定义编码
            elif "base64" in q_lower or "字符表" in q_lower:
                for ev in evidence_list:
                    if ev.type == 'Webshell_Custom_Base64':
                        answer = f"检测到自定义Base64，字符表: {ev.details.get('alphabet_detected')}"
                        pkt = ev.packet_num
                        break
            
            answers.append({
                "question": q,
                "answer": answer,
                "evidence_pkt": pkt,
                "technique": "local_rule"
            })
        
        return {"answers": answers}


# ========== 主程序 ==========
def main():
    """主程序入口"""
    try:
        if len(sys.argv) < 2:
            print("Usage: python ctf_battle_v5.py <network.pcapng> [--questions file.txt]")
            print("\n战场级特性:")
            print("  ✓ 纯Python解析，零tshark依赖")
            print("  ✓ ICMP/DNS隧道自动检测")
            print("  ✓ 自定义Base64字符表破解")
            print("  ✓ 大文件流式处理")
            sys.exit(1)
        
        pcap_path = sys.argv[1]
        
        # 检查文件
        if not os.path.exists(pcap_path):
            print(f"[!] 文件不存在: {pcap_path}", flush=True)
            sys.exit(1)
        
        # 检查文件大小
        file_size = os.path.getsize(pcap_path)
        if file_size > MAX_MEMORY_MB * 1024 * 1024:
            logger.warning(f"文件大小 {file_size/1024/1024:.1f}MB 超过内存限制 {MAX_MEMORY_MB}MB，可能影响性能")
        
        # 加载问题
        questions = []
        if "--questions" in sys.argv:
            idx = sys.argv.index("--questions")
            qfile = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else None
            if qfile and os.path.exists(qfile):
                with open(qfile, 'r', encoding='utf-8') as f:
                    questions = [l.strip() for l in f if l.strip() and not l.startswith('#')]
        
        if not questions:
            questions = [
                "检测到ICMP隧道了吗？如果检测到，类型是什么？",
                "DNS隧道使用的工具推测是什么？",
                "是否存在自定义Base64编码的Webshell？字符表是什么？",
                "被扫描的IP地址是？",
                "木马上传的绝对路径是？"
            ]
        
        # 分析
        print(f"[*] 启动战场级分析: {pcap_path}")
        print(f"[*] 文件大小: {file_size/1024/1024:.1f} MB")
        
        engine = BattleForensicsEngine(pcap_path)
        evidence_list = list(engine.analyze())
        
        # AI分析
        print("[*] 准备进行AI分析（如果配置了API）...")
        expert = BattleAIExpert()
        if not expert.use_ai:
            print("[!] 未检测到AI配置，将使用本地规则分析")
        else:
            print("[*] AI配置可用，正在联网分析... (请稍候)")
        result = expert.analyze(evidence_list, questions, pcap_path)
        
        # 输出
        print("\n" + "="*60)
        print("战场级取证分析报告")
        print("="*60)
        
        for ans in result.get("answers", []):
            print(f"\n[题] {ans.get('question', 'N/A')}")
            print(f"[答] {ans.get('answer', 'N/A')}")
            if ans.get('evidence_pkt'):
                print(f"[证据] 包号 #{ans.get('evidence_pkt')}")
            if ans.get('technique'):
                print(f"[技术] {ans.get('technique')}")
        
        # 保存
        report_file = f"battle_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump({
                "evidence": [e.__dict__ for e in evidence_list],
                "result": result,
                "questions": questions
            }, f, ensure_ascii=False, indent=2)
        
        print(f"\n[+] 完整报告: {report_file}")
        print(f"[+] 证据数量: {len(evidence_list)}")
        
    except KeyboardInterrupt:
        print("\n[!] 用户中断分析")
        sys.exit(1)
    except Exception as e:
        print(f"[!] 错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()