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
        f.write("## 订阅链接\n")
        f.write("1. AdGuard Home 等DNS拦截服务使用规则1\n")
        f.write("2. AdGuard 等浏览器插件使用规则1 + 规则2\n\n")
        f.write("| 规则 | 原始链接 | 加速链接 |\n")
        f.write("|:-|:-|:-|\n")
        f.write("| 规则1：DNS 拦截 | [原始链接](https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt) | [加速链接](https://ghproxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt) |\n")
        f.write("| 规则2：插件拦截 | [原始链接](https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilters.txt) | [加速链接](https://ghproxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilters.txt) |\n")
        f.write("## 规则源\n")
        f.write("1. 不再引用[anti-AD](https://anti-ad.net/adguard.txt)、[yhosts](https://raw.githubusercontent.com/VeleSila/yhosts/master/hosts.txt)，具体原因见[Mosney/anti-anti-AD](https://github.com/Mosney/anti-anti-AD)。\n")
        f.write("2. 移除[Notracking blocklist](https://raw.githubusercontent.com/notracking/hosts-blocklists/master/adblock/adblock.txt)，原项目[已停止维护](https://github.com/notracking/hosts-blocklists/issues/900)。\n")
        f.write("\n")
        f.write("| 规则 | 类型 | 原始链接 | 加速链接 | 更新日期 |\n")
        f.write("|:-|:-|:-|:-|:-|\n")
        for rule in ruleList:
            f.write("| %s | %s | [原始链接](%s) | [加速链接](https://ghproxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/%s.txt) | %s |\n" % (rule[0],rule[1],rule[2],rule[0].replace(' ', '_'),rule[3]))

def GetBlackList():
    blackList = []
    fileName = os.getcwd() + "/rules/black.txt"
    if os.path.exists(fileName):
        with open(fileName, 'r') as f:
            blackList = f.readlines()
            blackList = list(map(lambda x: x.replace("\n", ""), blackList))
    return blackList

def CreatDNS(blockDict, unblockDict, fileName):
    # 去重、排序
    def sort(domainDict, isBlock, blackList):
        blockList = []
        fldList = []
        for item in domainDict:
            fldList.append(item)
        fldList.sort() # 排序
        for fld in fldList:
            subdomainList = list(set(domainDict[fld])) # 去重
            if '' in subdomainList: # 二级域名已被拦截，则干掉所有子域名
                subdomainList = ['']
            subdomainList = list(filter(None, subdomainList)) # 去空
            if len(subdomainList) > 0:
                subdomainList.sort() # 排序
                for subdomain in subdomainList:
                    if "%s.%s"%(subdomain, fld) in blackList:
                        continue
                    if isBlock:
                        blockList.append("||%s.%s^"%(subdomain, fld))
                    else:
                        blockList.append("@@||%s.%s^"%(subdomain, fld))
            else:
                if fld in blackList:
                    continue
                if isBlock:
                    blockList.append("||%s^"%(fld))
                else:
                    blockList.append("@@||%s^"%(fld))
        return blockList
    
    # 备份全量域名，用于检查域名有效性生成黑名单
    blockList = sort(blockDict, True, [])
    unblockList = sort(unblockDict, False, [])
    backupName = fileName[:-len("txt")] + "backup"
    if os.path.exists(backupName):
        os.remove(backupName)
    with open(backupName, 'a') as f:
        for fiter in blockList:
            f.write("%s\n"%(fiter))
        for fiter in unblockList:
            f.write("%s\n"%(fiter)) 

    blackList = GetBlackList()
    blockList = sort(blockDict, True, blackList)
    unblockList = sort(unblockDict, False, blackList)
    if os.path.exists(fileName):
        os.remove(fileName)
    
    with open(fileName, 'a') as f:
        f.write("!\n")
        f.write("! Title: AdBlock DNS\n")
        f.write("! Description: 适用于AdGuard的去广告合并规则，每8个小时更新一次。规则源：1Hosts (Lite)、ADgk、AdGuard Base filter、AdGuard Base filter、AdGuard DNS filter、AdRules DNS List、Hblock、NEO DEV HOST、OISD Basic、1024 hosts、ad-wars hosts、StevenBlack hosts、xinggsf、EasyList、Easylist China、EasyPrivacy、CJX's Annoyance List、SmartTV Blocklist\n")
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
        f.write("! Description: 适用于AdGuard的去广告合并规则，每8个小时更新一次。规则源：1Hosts (Lite)、ADgk、AdGuard Base filter、AdGuard Base filter、AdGuard DNS filter、AdRules DNS List、Hblock、NEO DEV HOST、OISD Basic、1024 hosts、ad-wars hosts、StevenBlack hosts、xinggsf、EasyList、Easylist China、EasyPrivacy、CJX's Annoyance List、SmartTV Blocklist\n")
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
        relue = Rule(ruleList[i][0], ruleList[i][2])
        if relue.Update():
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