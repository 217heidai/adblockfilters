"""blacklist.py 回归测试（review 第二轮 finding 1、3）

用法：python test_blacklist.py，失败时非零退出。
"""

import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from blacklist import _blacklist_abnormal, BlackList

failures = 0


def check(name, cond):
    global failures
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        failures += 1


# --- finding 3：阈值判断 ---
check("3a 正常 16% 不异常", not _blacklist_abnormal(61000, 390000))
check("3b 60% 异常", _blacklist_abnormal(234000, 390000))
check("3c 刚好一半不异常", not _blacklist_abnormal(195000, 390000))
check("3d 一半多一个异常", _blacklist_abnormal(195001, 390000))
check("3e 0 不异常", not _blacklist_abnormal(0, 390000))
check("3f 全部失败异常", _blacklist_abnormal(390000, 390000))

# --- finding 1：空输入 fail fast ---
tmp = tempfile.mkdtemp(prefix="bl-test-")

# 1a：domain.txt 为空 -> generate() 报错而不是静默 return
open(os.path.join(tmp, "domain.txt"), "w").write("")
bl = BlackList(tmp)
try:
    bl.generate()
    check("1a 空 domain.txt 报错", False)
except Exception as e:
    check("1a 空 domain.txt 报错", "domain list empty" in str(e))
bl.close()

# 1b/1c：direct.txt / ipv4_china.txt 下载失败且无本地文件 -> 报错
bl2 = BlackList(tmp)
bl2._BlackList__directlistUrl = "http://127.0.0.1:9/direct.txt"
bl2._BlackList__IPlistUrl = "http://127.0.0.1:9/ipv4_china.txt"
try:
    bl2._BlackList__getDomainSet_CN()
    check("1b direct.txt 下载失败无本地文件报错", False)
except Exception as e:
    check("1b direct.txt 下载失败无本地文件报错", "direct.txt unavailable" in str(e))
try:
    bl2._BlackList__getIPDict_CN()
    check("1c ipv4_china.txt 下载失败无本地文件报错", False)
except Exception as e:
    check("1c ipv4_china.txt 下载失败无本地文件报错", "ipv4_china.txt unavailable" in str(e))
bl2.close()

# 1d：下载失败但本地有旧文件 -> 不报错，用旧文件
os.makedirs(os.path.join(tmp, "rules"), exist_ok=True)
open(os.path.join(tmp, "rules", "direct.txt"), "w").write("domain:qq.com\n")
bl3 = BlackList(tmp)
bl3._BlackList__directlistUrl = "http://127.0.0.1:9/direct.txt"
full, dom, rx, kw = bl3._BlackList__getDomainSet_CN()
check("1d 下载失败有本地文件时用旧文件", "qq.com" in dom)
bl3.close()

# 1e：Content-Type 非文本 -> 下载拒绝，不写文件
class HtmlHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html>error</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


srv = HTTPServer(("127.0.0.1", 0), HtmlHandler)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
bl4 = BlackList(tmp)
target = os.path.join(tmp, "rules", "ipv4_china.txt")
if os.path.exists(target):
    os.remove(target)
ok = bl4._BlackList__download(target, "http://127.0.0.1:%d/ipv4_china.txt" % port)
check("1e 非文本 Content-Type 拒绝下载", ok is False and not os.path.exists(target))
srv.shutdown()
bl4.close()

print("\n%d failures" % failures)
sys.exit(1 if failures else 0)
