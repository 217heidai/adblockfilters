"""resolver.py / app/base.py 回归测试（问题 1、2、3 的最小用例）

用法：python test_resolver.py，失败时非零退出。
覆盖：带路径规则不再整域拦截/放行（问题 1）、无结尾 ^ 的 @@|| 规则
不再丢弃（问题 2）、$option 域名提取不再依赖选项枚举（问题 3a）、
通用 $ 规则按 domain= 判断是否进 Lite（问题 3b）。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from resolver import Resolver
from app.adguard import AdGuard

failures = []


def check(name, got, want):
    if got != want:
        failures.append("%s: got %r, want %r" % (name, got, want))
        print("FAIL %s" % name)
    else:
        print("PASS %s" % name)


r = Resolver(".")

# 问题 1：带路径规则只针对路径，不拦截/放行整域
block, unblock, f = r._Resolver__resolveDNS("||example.org/path^")
check("1a path rule not block", block, None)
check("1b path rule is filter", f, ("||example.org/path^", "example.org"))
block, unblock, f = r._Resolver__resolveDNS("@@||example.org/path^")
check("1c path allow not unblock", unblock, None)
check("1d path allow is filter", f, ("@@||example.org/path^", "example.org"))

# 问题 2：无结尾 ^ 的 @@|| 规则保留为 filter；有 ^ 的同样保留
block, unblock, f = r._Resolver__resolveDNS("@@||clients2.googleusercontent.com/crx/blobs/Ad_*")
check("2a @@|| no ^ kept as filter", f[0], "@@||clients2.googleusercontent.com/crx/blobs/Ad_*")
block, unblock, f = r._Resolver__resolveDNS("@@||clients2.googleusercontent.com/crx/blobs/Ad_*^")
check("2b @@|| with ^ kept as filter", f[0], "@@||clients2.googleusercontent.com/crx/blobs/Ad_*^")

# 0d36681 回归：锚定放行仍生效；普通拦截不受影响
block, unblock, f = r._Resolver__resolveDNS("@@||sponsor.nitropay.com^|")
check("0d36681 anchored allow", unblock, ("nitropay.com", "sponsor"))
block, unblock, f = r._Resolver__resolveDNS("||doubleclick.net^")
check("control plain block", block, ("doubleclick.net", ""))

# 问题 3a：$option 域名提取不再依赖选项枚举
for opt in ["replace", "csp", "media", "cookie", "important", "badfilter",
            "removeparam", "removeheader", "rewrite", "header", "jsinject",
            "content", "extension", "network", "app", "font", "empty", "xhr",
            "referrerpolicy", "redirect-rule", "~media", "~document", "~ping"]:
    _, domain = r._Resolver__resolveFilterDomain("||example.org^$%s" % opt)
    check("3a $%s domain" % opt, domain, "example.org")

# 问题 3b：通用 $ 规则按 domain= 判断是否进 Lite
CN = {"qq.com"}


def lite_list(filterDict, filterList):
    g = AdGuard([], [], filterDict, filterList, [], CN, "out/adblockfilters.txt", "test")
    return g.filterListLite


check("3b foreign domain= not in Lite",
      lite_list({"$cookie=foo,domain=slate.com": None}, ["$cookie=foo,domain=slate.com"]), [])
check("3b CN domain= in Lite",
      lite_list({"$cookie=foo,domain=qq.com": None}, ["$cookie=foo,domain=qq.com"]),
      ["$cookie=foo,domain=qq.com"])
check("3b no domain= kept (conservative)",
      lite_list({"$removeparam=x": None}, ["$removeparam=x"]), ["$removeparam=x"])
check("3b all-negated domain= kept",
      lite_list({"$cookie=foo,domain=~slate.com": None}, ["$cookie=foo,domain=~slate.com"]),
      ["$cookie=foo,domain=~slate.com"])
check("3b CN $replace in Lite, foreign $replace not",
      lite_list({"||qq.com^$replace": "qq.com", "||iprima.cz^$replace": "iprima.cz"},
                ["||qq.com^$replace", "||iprima.cz^$replace"]),
      ["||qq.com^$replace"])

print("\n%d failures" % len(failures))
for f in failures:
    print(" -", f)
sys.exit(1 if failures else 0)
