import re
import os
from typing import List

from loguru import logger

class Rule(object):
    def __init__(self, name:str, type:str, url:str, latest:str, update:bool=False):
        self.name = name
        self.filename = self.name.replace(' ', '_') + '.txt'
        self.type = type
        self.url = url
        self.latest = latest
        self.update = update

# redme文件操作
class ReadMe(object):
    def __init__(self, filename:str):
        self.filename = filename
        self.ruleList:List[Rule] = []

    def getRules(self) -> List[Rule]:
        logger.info("resolve readme...")
        self.ruleList = []
        with open(self.filename, "r") as f:
            for line in f:
                line = line.replace('\r', '').replace('\n', '')
                if line.find('|')==0 and line.rfind('|')==len(line)-1:
                    rule = list(map(lambda x: x.strip(), line[1:].split('|')))
                    if rule[2].find('(') > 0 and rule[2].find(')') > 0 and len(rule) > 4:
                        url = rule[2][rule[2].find('(')+1:rule[2].find(')')]
                        matchObj1 = re.match('(http|https):\/\/[\w\-_]+(\.[\w\-_]+)+([\w\-\.,@?^=%&:/~\+#]*[\w\-\@?^=%&/~\+#])?', url)
                        if matchObj1:
                            self.ruleList.append(Rule(rule[0], rule[1], url, rule[4]))
        return self.ruleList
    
    def setRules(self, ruleList:List[Rule]):
        self.ruleList = ruleList
    
    def regenerate(self):
        logger.info("regenerate readme...")
        if os.path.exists(self.filename):
            os.remove(self.filename)
        
        with open(self.filename, 'a') as f:
            f.write("# AdBlock DNS Filters\n")
            f.write("适用于AdGuard的去广告合并规则，每8个小时更新一次。\n")
            f.write("个人收藏了不少广告过滤规则，但是每次往新设备添加的时候很是头疼，于是写了这个项目，定时自动获取各规则源更新，生成合并规则库。\n")
            f.write("\n")
            f.write("## 说明\n")
            f.write("1. 定时从上游各规则源获取更新，合并去重。\n")
            f.write("2. 使用国内、国外各 3 组 DNS 服务，分别对上游各规则源拦截的域名进行解析，去除已无法解析的域名。（上游各规则源中存在大量已无法解析的域名，无需加入拦截规则）\n")
            f.write("3. 本项目仅对上游规则进行合并、去重、去除无效域名，不做任何修改。如发现误拦截情况，可临时添加放行规则（如 `@@||www.example.com^$important`），并向上游规则反馈。\n")
            f.write("\n")
            f.write("## 订阅链接\n")
            f.write("1. AdGuard Home 等DNS拦截服务使用规则1\n")
            f.write("2. AdGuard 等浏览器插件使用规则1 + 规则2\n\n")
            f.write("| 规则 | 原始链接 | 加速链接 |\n")
            f.write("|:-|:-|:-|\n")
            f.write("| 规则1：DNS 拦截 | [原始链接](https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt) |\n")
            f.write("| 规则2：插件拦截 | [原始链接](https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilters.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilters.txt) |\n")
            f.write("\n")
            f.write("## 上游规则源\n")
            f.write("1. 感谢各位广告过滤规则维护大佬们的辛苦付出。\n")
            f.write("2. 不再引用[anti-AD](https://anti-ad.net/adguard.txt)、[yhosts](https://raw.githubusercontent.com/VeleSila/yhosts/master/hosts.txt)，具体原因见[Mosney/anti-anti-AD](https://github.com/Mosney/anti-anti-AD)。\n")
            f.write("3. 移除[Notracking blocklist](https://raw.githubusercontent.com/notracking/hosts-blocklists/master/adblock/adblock.txt)，原项目[已停止维护](https://github.com/notracking/hosts-blocklists/issues/900)。\n")
            f.write("4. 移除[ADgk](https://raw.githubusercontent.com/banbendalao/ADgk/master/ADgk.txt)，项目超过 1 年未更新。\n")
            f.write("\n")
            f.write("| 规则 | 类型 | 原始链接 | 加速链接 | 更新日期 |\n")
            f.write("|:-|:-|:-|:-|:-|\n")
            for rule in self.ruleList:
                f.write("| %s | %s | [原始链接](%s) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/%s) | %s |\n" % (rule.name,rule.type,rule.url,rule.filename,rule.latest))
            f.write("\n")
            f.write("## Star History\n")
            f.write("[![Star History Chart](https://api.star-history.com/svg?repos=217heidai/adblockfilters&type=Date)](https://star-history.com/#217heidai/adblockfilters&Date)\n")