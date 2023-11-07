import os
import re
import time
import json

from downloader import Downloader
from resolver import Resolver

def LoadSubscriptionMapping():
    with open('subscription_mapping.json', 'r') as mapping_file:
        subscription_mapping = json.load(mapping_file)
    return subscription_mapping

def GetRuleList(subscriptions_file, subscription_mapping):
        ruleList = []
        with open(subscriptions_file, "r") as f:
            for line in f:
                line = line.replace('\r', '').replace('\n', '')
                if line in subscription_mapping:
                    rule_name = line  # 使用订阅链接作为规则名称
                    url = subscription_mapping[line]  # 获取订阅链接
                    ruleList.append([url, rule_name])
        return ruleList

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

def CreatReadme(ruleList, fileName):
    if os.path.exists(fileName):
        os.remove(fileName)

    with open(fileName, 'a') as f:
        f.write("# AdBlock DNS Filters\n")
        f.write("适用于AdGuard的去广告合并规则，每8个小时更新一次。\n")
        f.write("## 订阅链接\n")
        f.write("| 规则 | 原始链接 |\n")
        f.write("|:-|:-|:-|\n")
        for i, rule in enumerate(ruleList, 1):
            f.write(f"| 规则{i} | [原始链接]({rule[2]}) |\n")

def GetBlackList():
    blackList = []
    fileName = os.getcwd() + "/rules/black.txt"
    if os.path.exists(fileName):
        with open(fileName, 'r') as f:
            blackList = f.readlines()
            blackList = list(map(lambda x: x.replace("\n", ""), blackList))
    return blackList

def CreatDNS(blockDict, unblockDict, fileName):
    def sort(domainDict, isBlock, blackList):
        blockList = []
        fldList = []
        for item in domainDict:
            fldList.append(item)
        fldList.sort()
        for fld in fldList:
            subdomainList = list(set(domainDict[fld]))
            if '' in subdomainList:
                subdomainList = ['']
            subdomainList = list(filter(None, subdomainList))
            if len(subdomainList) > 0:
                subdomainList.sort()
                for subdomain in subdomainList:
                    if "%s.%s" % (subdomain, fld) in blackList:
                        continue
                    if isBlock:
                        blockList.append("||%s.%s^" % (subdomain, fld))
                    else:
                        blockList.append("@@||%s.%s^" % (subdomain, fld))
            else:
                if fld in blackList:
                    continue
                if isBlock:
                    blockList.append("||%s^" % (fld))
                else:
                    blockList.append("@@||%s^" % (fld))
        return blockList

    blockList = sort(blockDict, True, [])
    unblockList = sort(unblockDict, False, [])
    backupName = fileName[:-len("txt")] + "backup"
    if os.path.exists(backupName):
        os.remove(backupName)
    with open(backupName, 'a') as f:
        for fiter in blockList:
            f.write("%s\n" % (fiter))
        for fiter in unblockList:
            f.write("%s\n" % (fiter))

    blackList = GetBlackList()
    blockList = sort(blockDict, True, blackList)
    unblockList = sort(unblockDict, False, blackList)
    if os.path.exists(fileName):
        os.remove(fileName)

    with open(fileName, 'a') as f:
        f.write("!\n")
        f.write("! Title: AdBlock DNS\n")
        f.write("! Description: 适用于AdGuard的去广告合并规则，每8个小时更新一次。\n")
        f.write("! Homepage: https://github.com/Claire9518/adblockfilters\n")
        f.write("! Source: https://raw.githubusercontent.com/Claire9518/adblockfilters/main/rules/adblockdns.txt\n")
        f.write("! Version: %s\n" % (time.strftime("%Y%m%d%H%M%S", time.localtime())))
        f.write("! Last modified: %s\n" % (time.strftime("%Y/%m/%d %H:%M:%S", time.localtime())))
        f.write("! Blocked domains: %s\n" % (len(blockList)))
        f.write("! unBlocked domains: %s\n" % (len(unblockList)))
        f.write("!\n")
        for fiter in blockList:
            f.write("%s\n" % (fiter))
        for fiter in unblockList:
            f.write("%s\n" % (fiter))

def CreatFilter(filterList, fileName):
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
        f.write("! Description: 适用于AdGuard的去广告合并规则，每8个小时更新一次。\n")
        f.write("! Homepage: https://github.com/Claire9518/adblockfilters\n")
        f.write("! Source: https://raw.githubusercontent.com/Claire9518/adblockfilters/main/rules/adblockdns.txt\n")
        f.write("! Version: %s\n" % (time.strftime("%Y%m%d%H%M%S", time.localtime())))
        f.write("! Last modified: %s\n" % (time.strftime("%Y/%m/%d %H:%M:%S", time.localtime())))
        f.write("! Blocked Filters: %s\n" % (len(filterList)))
        f.write("!\n")
        for fiter in filterList:
            f.write("%s\n" % (fiter))

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
    subscriptions_file = pwd + '/subscriptions.txt'
    
    subscription_mapping = LoadSubscriptionMapping()  # 移动这行到Entry函数内

    ruleList = GetRuleList(subscriptions_file, subscription_mapping)  # 传递subscription_mapping参数

    isUpdate = False
    lastUpdate = time.strftime("%Y/%m/%d", time.localtime())
    for i in range(0, len(ruleList)):
        rule = Rule(ruleList[i][0], ruleList[i][1])  # 这里改成ruleList[i][1]，因为它包含了URL
        if rule.Update():
            isUpdate = True
            # ruleList[i][2] = lastUpdate

    if isUpdate:
        blockDict = dict()
        unblockDict = dict()
        filterList = []
        for i in range(0, len(ruleList)):
            resolver = Resolver(os.getcwd() + '/rules/' + ruleList[i][0].replace(' ', '_') + '.txt')
            d1, d2, l3 = resolver.Resolve(ruleList[i][1])
            print('%s: block[%s], unblock[%s], filter[%s]' % (ruleList[i][0], len(d1), len(d2), len(l3)))
            blockDict = dictadd(blockDict, d1)
            unblockDict = dictadd(unblockDict, d2)
            filterList += l3

        CreatDNS(blockDict, unblockDict, pwd + '/rules/adblockdns.txt')
        CreatFilter(filterList, pwd + '/rules/adblockfilters.txt')
        CreatReadme(ruleList, pwd + '/README.md')

if __name__ == '__main__':

    subscription_mapping = LoadSubscriptionMapping()
    subscriptions_file = os.getcwd() + '/subscriptions.txt'

    ruleList = GetRuleList(subscriptions_file, subscription_mapping)

    Entry()
