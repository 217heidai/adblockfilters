import os
import re
import time

from downloader import Downloader
from resolver import Resolver


class Rule(object):
    def __init__(self, name, url):
        self.Name = name
        self.FileName = self.Name.replace(' ', '_') + '.txt'
        self.URL = url
        self.Downloader = Downloader(os.getcwd() + '/rules/' + self.FileName, self.URL)

    def Update(self):
        if self.Downloader.Download():
            return True
        return False

def GetRuleList(fileName):
    ruleList = []
    with open(fileName, "r") as f:
        for line in f:
            line = line.replace('\r', '').replace('\n', '')
            if line.find('|')==0 and line.rfind('|')==len(line)-1:
                rule = list(map(lambda x: x.strip(), line[1:].split('|')))
                if rule[2].find('(') > 0 and rule[2].find(')') > 0 and len(rule) > 4:
                    url = rule[2][rule[2].find('(')+1:rule[2].find(')')]
                    matchObj1 = re.match('(http|https):\/\/[\w\-_]+(\.[\w\-_]+)+([\w\-\.,@?^=%&:/~\+#]*[\w\-\@?^=%&/~\+#])?', url)
                    if matchObj1:
                        ruleList.append([rule[0], rule[1], url, rule[4]])
    return ruleList

def CreatReadme(ruleList, fileName):
    if os.path.exists(fileName):
        os.remove(fileName)
    
    with open(fileName, 'a') as f:
        f.write("# AdBlock DNS Filters\n")
        f.write("适用于AdGuard的去广告合并规则，每8个小时更新一次。\n")
        f.write("个人收藏了不少广告过滤规则，但是每次往新设备添加的时候很是头疼，于是写了这个项目，定时自动获取各规则源更新，生成合并规则库。\n")
        f.write("## 说明\n")
        f.write("1. 定时从上游各规则源获取更新，合并去重。\n")
        f.write("2. 使用两组国内、两组国外 DNS 服务，分别对上游各规则源拦截的域名进行解析，去除已无法解析的域名。（上游各规则源中存在大量已无法解析的域名，无需加入拦截规则）\n")
        f.write("3. 本项目仅对上游规则进行合并、去重、去除无效域名，不做任何修改。如发现误拦截情况，可临时添加放行规则（如 `@@||www.example.com^$important`），并向上游规则反馈。\n\n")
        f.write("## 订阅链接\n")
        f.write("1. AdGuard Home 等DNS拦截服务使用规则1\n")
        f.write("2. AdGuard 等浏览器插件使用规则1 + 规则2\n\n")
        f.write("| 规则 | 原始链接 | 加速链接 |\n")
        f.write("|:-|:-|:-|\n")
        f.write("| 规则1：DNS 拦截 | [原始链接](https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt) |\n")
        f.write("| 规则2：插件拦截 | [原始链接](https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilters.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilters.txt) |\n")
        f.write("## 上游规则源\n")
        f.write("1. 感谢各位广告过滤规则维护大佬们的辛苦付出。\n")
        f.write("2. 不再引用[anti-AD](https://anti-ad.net/adguard.txt)、[yhosts](https://raw.githubusercontent.com/VeleSila/yhosts/master/hosts.txt)，具体原因见[Mosney/anti-anti-AD](https://github.com/Mosney/anti-anti-AD)。\n")
        f.write("3. 移除[Notracking blocklist](https://raw.githubusercontent.com/notracking/hosts-blocklists/master/adblock/adblock.txt)，原项目[已停止维护](https://github.com/notracking/hosts-blocklists/issues/900)。\n")
        f.write("4. 移除[ADgk](https://raw.githubusercontent.com/banbendalao/ADgk/master/ADgk.txt)，项目超过 1 年未更新。\n")
        f.write("\n")
        f.write("| 规则 | 类型 | 原始链接 | 加速链接 | 更新日期 |\n")
        f.write("|:-|:-|:-|:-|:-|\n")
        for rule in ruleList:
            f.write("| %s | %s | [原始链接](%s) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/%s.txt) | %s |\n" % (rule[0],rule[1],rule[2],rule[0].replace(' ', '_'),rule[3]))

def GetBlackList():
    blackList = []
    fileName = os.getcwd() + "/rules/black.txt"
    if os.path.exists(fileName):
        with open(fileName, 'r') as f:
            blackList = f.readlines()
            blackList = list(map(lambda x: x.replace("\n", ""), blackList))
    return blackList

def GetWhiteList():
    whiteList = []
    fileName = os.getcwd() + "/rules/white.txt"
    if os.path.exists(fileName):
        with open(fileName, 'r') as f:
            for line in f.readlines():
                if not line.startswith("#") and len(line.replace("\n", "")) > 4:
                    whiteList.append(line.replace("\n", ""))
    return whiteList

# 去重、排序
def sort(domainDict, isBlock, blackList, whiteList):
    def repetition(l):
        tmp = []
        for i in l:
            for j in l:
                if len(i) > len(j) and i.rfind("." + j) == len(i) - len(j) - 1:
                    tmp.append(i)
                    break
        return list(set(l)-set(tmp))
    blockList = []
    blockList_all = []
    fldList = []
    for item in domainDict:
        fldList.append(item)
    fldList.sort() # 排序
    for fld in fldList:
        subdomainList = list(set(domainDict[fld])) # 去重
        if '' in subdomainList and fld not in whiteList: # 二级域名已被拦截，则干掉所有子域名
            subdomainList = ['']
        subdomainList = list(filter(None, subdomainList)) # 去空
        if len(subdomainList) > 0:
            if len(subdomainList) > 2:
                subdomainList = repetition(subdomainList) # 短域名已被拦截，则干掉所有长域名。如'a.example'、'b.example'、'example'，则只保留'example'
            subdomainList.sort() # 排序
            for subdomain in subdomainList:
                item = "%s.%s"%(subdomain, fld)
                if isBlock:
                    blockList_all.append("||%s^"%(item))
                else:
                    blockList_all.append("@@||%s^"%(item))
                
                if item not in blackList and item not in whiteList:
                    if isBlock:
                        blockList.append("||%s^"%(item))
                    else:
                        blockList.append("@@||%s^"%(item))
        else:
            item = "%s"%(fld)
            if isBlock:
                blockList_all.append("||%s^"%(item))
            else:
                blockList_all.append("@@||%s^"%(item))
            
            if item not in blackList and item not in whiteList:
                if isBlock:
                    blockList.append("||%s^"%(item))
                else:
                    blockList.append("@@||%s^"%(item))
    
    return blockList,blockList_all

def CreatDNS(blockDict, unblockDict, fileName):
    blackList = GetBlackList()
    whiteList = GetWhiteList()
    blockList,blockList_all = sort(blockDict, True, blackList, whiteList)
    unblockList,unblockList_all = sort(unblockDict, False, blackList, whiteList)

    # 备份全量域名，用于检查域名有效性生成黑名单
    backupName = fileName[:-len("txt")] + "backup"
    if os.path.exists(backupName):
        os.remove(backupName)
    with open(backupName, 'a') as f:
        for fiter in blockList_all:
            f.write("%s\n"%(fiter))
        for fiter in unblockList_all:
            f.write("%s\n"%(fiter))

    # 生成规则文件
    if os.path.exists(fileName):
        os.remove(fileName)    
    with open(fileName, 'a') as f:
        f.write("!\n")
        f.write("! Title: AdBlock DNS\n")
        f.write("! Description: 适用于AdGuard的去广告合并规则，每8个小时更新一次。规则源：1Hosts (Lite)、AdGuard Base filter、AdGuard Base filter、AdGuard DNS filter、AdRules DNS List、Hblock、NEO DEV HOST、OISD Basic、1024 hosts、ad-wars hosts、StevenBlack hosts、xinggsf、EasyList、Easylist China、EasyPrivacy、CJX's Annoyance List、SmartTV Blocklist、AWAvenue Ads Rule、jiekouAD\n")
        f.write("! Homepage: https://github.com/217heidai/adblockfilters\n")
        f.write("! Source: https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt\n")
        f.write("! Version: %s\n"%(time.strftime("%Y%m%d%H%M%S", time.localtime())))
        f.write("! Last modified: %s\n"%(time.strftime("%Y/%m/%d %H:%M:%S", time.localtime())))
        f.write("! Blocked domains: %s\n"%(len(blockList)))
        f.write("! unBlocked domains: %s\n"%(len(unblockList)))
        f.write("!\n")
        for fiter in blockList:
            f.write("%s\n"%(fiter))
        for fiter in unblockList:
            f.write("%s\n"%(fiter))

def CreatFiter(filterList, fileName):
    # 去重、排序
    def sort(L):
        L = list(set(L))
        L.sort()
        return L

    filterList = sort(filterList)

    if os.path.exists(fileName):
        os.remove(fileName)
    
    with open(fileName, 'a') as f:
        f.write("!\n")
        f.write("! Title: AdBlock Filter\n")
        f.write("! Description: 适用于AdGuard的去广告合并规则，每8个小时更新一次。规则源：1Hosts (Lite)、AdGuard Base filter、AdGuard Base filter、AdGuard DNS filter、AdRules DNS List、Hblock、NEO DEV HOST、OISD Basic、1024 hosts、ad-wars hosts、StevenBlack hosts、xinggsf、EasyList、Easylist China、EasyPrivacy、CJX's Annoyance List、SmartTV Blocklist、AWAvenue Ads Rule、jiekouAD\n")
        f.write("! Homepage: https://github.com/217heidai/adblockfilters\n")
        f.write("! Source: https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilters.txt\n")
        f.write("! Version: %s\n"%(time.strftime("%Y%m%d%H%M%S", time.localtime())))
        f.write("! Last modified: %s\n"%(time.strftime("%Y/%m/%d %H:%M:%S", time.localtime())))
        f.write("! Blocked Filters: %s\n"%(len(filterList)))
        f.write("!\n")
        for fiter in filterList:
            f.write("%s\n"%(fiter))

def Entry():
    def dictadd(d1, d2):
        d3 = dict()
        for item in d1:
            d3[item] = d1[item]
            if item in d2:
                d3[item] += d2[item]
        for item in d2:
            if item not in d1:
                d3[item] = d2[item]
        return d3
    pwd = os.getcwd()
    ruleFile = pwd + '/README.md'

    ruleList = GetRuleList(ruleFile)

    isUpdate = False
    lastUpdate = time.strftime("%Y/%m/%d", time.localtime())
    for i in range(0, len(ruleList)):
        rule = Rule(ruleList[i][0], ruleList[i][2])
        if rule.Update():
            isUpdate = True
            ruleList[i][3] = lastUpdate
    
    if isUpdate:
        blockDict = dict()
        unblockDict = dict()
        filterList = []
        for i in range(0, len(ruleList)):
            resolver = Resolver(os.getcwd() + '/rules/' + ruleList[i][0].replace(' ', '_') + '.txt')
            d1, d2, l3 = resolver.Resolve(ruleList[i][1])
            print('%s: block[%s],unblock[%s],filter[%s]'%(ruleList[i][0], len(d1), len(d2), len(l3)))
            blockDict = dictadd(blockDict, d1)
            unblockDict = dictadd(unblockDict, d2)
            filterList += l3

        # 生成合并规则
        CreatDNS(blockDict, unblockDict, pwd + '/rules/adblockdns.txt')
        CreatFiter(filterList, pwd + '/rules/adblockfilters.txt')

        # 更新README.md
    CreatReadme(ruleList, pwd + '/README.md')

if __name__ == '__main__':
    Entry()
