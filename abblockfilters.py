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
                if rule[1].find('(') > 0 and rule[1].find(')') > 0:
                    url = rule[1][rule[1].find('(')+1:rule[1].find(')')]
                    matchObj1 = re.match('(http|https):\/\/[\w\-_]+(\.[\w\-_]+)+([\w\-\.,@?^=%&:/~\+#]*[\w\-\@?^=%&/~\+#])?', url)
                    if matchObj1:
                        ruleList.append([rule[0], url, rule[3]])
    return ruleList

def CreatReadme(ruleList, fileName):
    if os.path.exists(fileName):
        os.remove(fileName)
    
    f = open(fileName, 'a')
    f.write("# AdBlock DNS Filters\n")
    f.write("适用于AdGuard的去广告合并规则，每8个小时更新一次。\n")
    f.write("个人收藏了不少广告过滤规则，但是每次往新设备添加的时候很是头疼，于是写了这个项目，定时自动获取各规则源更新，生成合并规则库。\n")
    f.write("## 订阅链接\n")
    f.write("- [原始链接](https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilters.txt)\n")
    f.write("- [加速链接](https://ghproxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilters.txt)\n")
    f.write("## 规则源\n")
    f.write("| 规则 | 原始链接 | 加速链接 | 更新日期 |\n")
    f.write("|:-|:-|:-|:-|\n")
    for rule in ruleList:
        f.write("| %s | [原始链接](%s) | [加速链接](https://ghproxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/%s.txt) | %s |\n" % (rule[0],rule[1],rule[0].replace(' ', '_'),rule[2]))
    f.close()

def CreatFiters(blockList, unblockList, fileName):
    # 去重、排序
    def sort(L):
        L = list(set(L))
        L.sort()
        return L
    blockList = sort(blockList)
    unblockList = sort(unblockList)

    if os.path.exists(fileName):
        os.remove(fileName)
    
    f = open(fileName, 'a')
    f.write("!\n")
    f.write("! Title: AdBlock DNS Filters\n")
    f.write("! Description: 适用于AdGuard的去广告合并规则，每8个小时更新一次。规则源：ADgk Filters、AdGuard DNS Filters、anti-AD Filters、NEO DEV HOST Filters、Hblock Filters、1024 hosts、ad-wars hosts、StevenBlack hosts、yhosts hosts\n")
    f.write("! Homepage: https://github.com/217heidai/adblockfilters\n")
    f.write("! Source: https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilters.txt\n")
    f.write("! Version: %s\n"%(time.strftime("%Y%m%d%H%M%S", time.localtime())))
    f.write("! Last modified: %s\n"%(time.strftime("%Y/%m/%d %H:%M:%S", time.localtime())))
    f.write("! Blocked domains: %s\n"%(len(blockList)+len(unblockList)))
    f.write("!\n")
    for fiter in blockList:
        f.write("%s\n"%(fiter))
    for fiter in unblockList:
        f.write("%s\n"%(fiter))
    f.close()

def Entry():
    pwd = os.getcwd()
    ruleFile = pwd + '/README.md'

    ruleList = GetRuleList(ruleFile)
    isUpdate = False
    lastUpdate = time.strftime("%Y/%m/%d", time.localtime())
    for i in range(0, len(ruleList)):
        relue = Rule(ruleList[i][0], ruleList[i][1])
        if relue.Update():
            isUpdate = True
            ruleList[i][2] = lastUpdate
    #isUpdate = True
    if isUpdate:
        blockList = []
        unblockList = []
        for i in range(0, len(ruleList)):
            resolver = Resolver(os.getcwd() + '/rules/' + ruleList[i][0].replace(' ', '_') + '.txt')
            L1, L2 = resolver.Resolve()
            blockList += L1
            unblockList += L2

        # 生成合并规则
        CreatFiters(blockList, unblockList, pwd + '/rules/adblockfilters.txt')

        # 更新README.md
        CreatReadme(ruleList, pwd + '/README.md')

if __name__ == '__main__':
    Entry()
