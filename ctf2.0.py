import re
import sys
from collections import defaultdict
from scapy.all import rdpcap, TCP, IP, Raw


class UltimateTrafficAnalyzer:

    def __init__(self):

        # SYN扫描统计
        self.syn_targets = defaultdict(int)
        self.scan_target = None

        # TCP流
        self.tcp_streams = defaultdict(bytes)

        # HTTP
        self.post_uris = []
        self.cookies = []

        # 凭证
        self.credentials_fail = []
        self.credentials_success = []

        # shell
        self.reverse_shell_outputs = []

        # hash
        self.shadow_hashes = []

        # answers
        self.answer_48 = None
        self.answer_49 = None
        self.answer_50 = None
        self.answer_51 = None
        self.answer_52 = None
        self.answer_53 = None


    # =========================
    # 端口扫描检测
    # =========================
    def detect_port_scan(self, pkt):

        if pkt.haslayer(IP) and pkt.haslayer(TCP):

            ip = pkt[IP]
            tcp = pkt[TCP]

            if tcp.flags == "S":
                self.syn_targets[ip.dst] += 1


    # =========================
    # TCP流重组
    # =========================
    def rebuild_stream(self, pkt):

        if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw):

            ip = pkt[IP]
            tcp = pkt[TCP]

            key = (
                ip.src,
                tcp.sport,
                ip.dst,
                tcp.dport
            )

            self.tcp_streams[key] += bytes(pkt[Raw].load)


    # =========================
    # HTTP解析
    # =========================
    def parse_http(self):

        for key, data in self.tcp_streams.items():

            try:
                text = data.decode(errors="ignore")
            except:
                continue

            # POST URI
            post_match = re.search(
                r"POST\s+([^\s]+)\s+HTTP",
                text
            )

            if post_match:
                uri = post_match.group(1)
                self.post_uris.append(uri)

            # 失败登录凭证
            creds = re.findall(
                r"(username|user|login)=([^&]+).*?(password|pass)=([^&\s]+)",
                text,
                re.I
            )

            for c in creds:
                user = c[1]
                pwd = c[3]
                self.credentials_fail.append((user, pwd))

            # 成功登录 + cookie
            if "HTTP/1.1 200" in text or "HTTP/1.1 302" in text:

                cookie_match = re.search(
                    r"Set-Cookie:\s*([^;\r\n]+)",
                    text,
                    re.I
                )

                if cookie_match:
                    cookie = cookie_match.group(1)
                    self.cookies.append(cookie)
                    self.credentials_success.append(cookie)


    # =========================
    # 反弹 shell 检测
    # =========================
    def detect_reverse_shell(self):

        for key, data in self.tcp_streams.items():

            try:
                text = data.decode(errors="ignore")
            except:
                continue

            if "/bin/sh" in text or "/bin/bash" in text:

                lines = text.splitlines()

                output = "\n".join(lines[-5:])

                self.reverse_shell_outputs.append(output)


    # =========================
    # shadow hash识别
    # =========================
    def detect_shadow_hash(self):

        hash_matches = re.findall(
            r"\$(\d+|[a-zA-Z])\$",
            str(self.tcp_streams)
        )

        algo_map = {
            "1": "MD5",
            "2": "BCRYPT",
            "2a": "BCRYPT",
            "5": "SHA256",
            "6": "SHA512"
        }

        for h in hash_matches:

            algo = algo_map.get(h, "UNKNOWN")
            self.shadow_hashes.append(algo)


    # =========================
    # 构建答案
    # =========================
    def build_answers(self):

        # Q48
        if self.credentials_fail:
            self.answer_48 = ":".join(self.credentials_fail[0])

        # Q49
        if self.credentials_success:
            self.answer_49 = self.credentials_success[0]

        # Q50
        if self.post_uris:
            self.answer_50 = self.post_uris[0]

        # Q51
        if self.syn_targets:
            self.scan_target = max(
                self.syn_targets,
                key=self.syn_targets.get
            )
            self.answer_51 = self.scan_target

        # Q52
        if self.shadow_hashes:
            self.answer_52 = self.shadow_hashes[0]

        # Q53
        if self.reverse_shell_outputs:
            self.answer_53 = self.reverse_shell_outputs[0]


    # =========================
    # 报告输出
    # =========================
    def report(self):

        print("\n===== Ultimate Traffic Analysis Report =====")

        print("Q48 Failed Credential:", self.answer_48)
        print("Q49 Success Cookie:", self.answer_49)
        print("Q50 POST URI:", self.answer_50)
        print("Q51 Scan Target IP:", self.answer_51)
        print("Q52 Shadow Hash Algo:", self.answer_52)

        print("\nQ53 Reverse Shell Output:")
        print(self.answer_53)

        print("\n============================================\n")


    # =========================
    # 主分析流程
    # =========================
    def analyze(self, pcap):

        packets = rdpcap(pcap)

        for pkt in packets:

            self.detect_port_scan(pkt)
            self.rebuild_stream(pkt)

        self.parse_http()
        self.detect_reverse_shell()
        self.detect_shadow_hash()

        self.build_answers()

        self.report()


# =========================
# MAIN
# =========================

if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage:")
        print("python analyzer_v4.py traffic.pcap")
        sys.exit()

    pcap_file = sys.argv[1]

    analyzer = UltimateTrafficAnalyzer()
    analyzer.analyze(pcap_file)