"""updater.py / adblock.py 回归测试（review 第二轮 finding 2）

用法：python test_updater.py，失败时非零退出。
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from readme import Rule
from updater import Updater

failures = 0


def check(name, cond):
    global failures
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        failures += 1


tmp = tempfile.mkdtemp(prefix="upd-test-")
src = os.path.join(tmp, "source")
os.makedirs(src)

# 2a/2b：死链接源记入 failedSources，不抛异常，不触发更新
dead = Rule("Dead Source", "dns", "http://127.0.0.1:9/does-not-exist.txt", "2026/01/01")
u = Updater([dead])
need, rules = u.update(src)
check("2a 死链接源记入 failedSources", u.failedSources == ["Dead Source"])
check("2b 死链接源不触发更新", need is False and rules[0].update is False)

# 2c/2d：refresh() 把失败源名写到 .cache/failed_sources.txt（即使无更新也写），且不污染 out 目录
from adblock import ADBlock

work = os.path.join(tmp, "work")
os.makedirs(os.path.join(work, ".cache", "source"), exist_ok=True)
open(os.path.join(work, "README.md"), "w").write(
    "# AdBlock DNS Filters\n\n"
    "| Dead Source | dns | [Dead Source](http://127.0.0.1:9/does-not-exist.txt) | 2026/01/01 |\n")
os.chdir(work)
ADBlock().refresh()
failed_file = os.path.join(work, ".cache", "failed_sources.txt")
check("2c refresh 写 failed_sources.txt",
      os.path.exists(failed_file) and open(failed_file).read().strip() == "Dead Source")
check("2d 无更新时 out 目录仍为空（不骗门控）",
      os.listdir(os.path.join(work, ".cache", "out")) == [])

print("\n%d failures" % failures)
sys.exit(1 if failures else 0)
