import os
import time
import re
from concurrent.futures import ThreadPoolExecutor,as_completed
from typing import List,Dict,Set,Tuple

from loguru import logger
from tld import get_tld

from readme import Rule
from resolver import Resolver

class Filter(object):
    def __init__(self, ruleList:List[Rule], path:str):
        self.ruleList = ruleList
        self.path = path
    
    # 获取拦截规则
    def __getFilters(self) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]], Dict[str, str]]:
        def dictadd(d1:Dict[str,Set], d2:Dict[str,Set]) -> Dict[str,Set]:
            d3 = dict()
            s = set.union(set(d1), set(d2))
            for item in s:
                d3[item] = set.union(d1.get(item, set()), d2.get(item, set()))
            return d3

        thread_pool = ThreadPoolExecutor(max_workers=os.cpu_count() if os.cpu_count() > 4 else 4)
        resolver = Resolver(self.path)
        # 线程池解析
        taskList = []
        for rule in self.ruleList:
            logger.info("resolve %s..."%(rule.name))
            if rule.type == "host":
                taskList.append(thread_pool.submit(resolver.resolveHost, rule))
            if rule.type == "dns":
                taskList.append(thread_pool.submit(resolver.resolveDNS, rule))
            if rule.type == "filter":
                taskList.append(thread_pool.submit(resolver.resolveFilter, rule))
        
        # 获取解析结果
        blockDict:Dict[str,Set[str]] = dict()
        unblockDict:Dict[str,Set[str]] = dict()
        filterDict:Dict[str,str] = dict()
        for future in as_completed(taskList):
            __blockDict,__unblockDict,__filterDict = future.result()
            blockDict = dictadd(blockDict, __blockDict)
            unblockDict = dictadd(unblockDict, __unblockDict)
            for filter,domain in __filterDict.items():
                filterDict[filter] = domain

        return blockDict,unblockDict,filterDict
    
    # 获取黑名单
    def __getBlackList(self, fileName:str) -> Set[str]:
        logger.info("resolve black list...")
        blackSet = set()
        if os.path.exists(fileName):
            with open(fileName, 'r') as f:
                blackList = f.readlines()
                blackSet = set(map(lambda x: x.replace("\n", ""), blackList))
        logger.info("black list: %d"%(len(blackSet)))
        return blackSet

    # 获取白名单
    def __getWhiteList(self, fileName:str) -> Set[str]:
        logger.info("resolve white list...")
        whiteSet = set()
        if os.path.exists(fileName):
            with open(fileName, 'r') as f:
                for line in f.readlines():
                    if not line.startswith("#") and len(line.replace("\n", "")) > 4:
                        whiteSet.add(line.replace("\n", ""))
        logger.info("white list: %d"%(len(whiteSet)))
        return whiteSet

    # 生成 dns 规则文件，同时返回全量域名
    def __generateDNS(self, blockDict:Dict[str, Set[str]], unblockDict:Dict[str, Set[str]], blackSet:Set[str], whiteSet:Set[str], fileName:str) -> Tuple[Set[str], Set[str]]:
        # 去重、排序
        def sort(domainDict:Dict[str, Set[str]], blackSet:Set[str], whiteSet:Set[str]) -> Tuple[List[str], Set[str]]:
            def repetition(l):
                if len(l) < 2:
                    return l
                tmp = set()
                for i in range(len(l) - 1):
                    for j in range(i+1, len(l)):
                        if re.match('.*\.%s$'%(l[i]), l[j]):
                            tmp.add(l[j])
                l = list(set(l)-tmp)
                l.sort()
                return l
            domanList = []
            domanSet_all = set()
            fldList = list(domainDict.keys())
            fldList.sort() # 排序
            for fld in fldList:
                subdomainList = sorted(list(domainDict[fld]), key = lambda item:len(item), reverse=False)
                if '' == subdomainList[0] and fld not in whiteSet: # 二级域名已被拦截，则干掉所有子域名。如二级域名在白名单中，则不拦截二级域名，只拦截三级域名
                    subdomainList = ['']
                subdomainList = list(filter(None, subdomainList)) # 去空
                if len(subdomainList) > 0:
                    subdomainList = repetition(subdomainList) # 短域名已被拦截，则干掉所有长域名。如'a.example'、'b.example'、'example'，则只保留'example'
                    for subdomain in subdomainList:
                        domain = "%s.%s"%(subdomain, fld)
                        if domain not in blackSet and domain not in whiteSet: # 剔除已无法访问的域名blackSet、需要保留的域名whiteSet
                            domanList.append(domain)
                        domanSet_all.add(domain)
                else:
                    domain = fld
                    if domain not in blackSet and domain not in whiteSet: # 剔除已无法访问的域名blackSet、需要保留的域名whiteSet
                        domanList.append(domain)
                    domanSet_all.add(domain)
            
            return domanList,domanSet_all

        logger.info("generate adblock dns...")

        blockList,blockSet_all = sort(blockDict, blackSet, whiteSet)
        unblockList,unblockSet_all = sort(unblockDict, blackSet, whiteSet)

        # 生成规则文件
        if os.path.exists(fileName):
            os.remove(fileName)    
        with open(fileName, 'a') as f:
            f.write("!\n")
            f.write("! Title: AdBlock DNS\n")
            f.write("! Description: 适用于AdGuard的去广告合并规则，每8个小时更新一次。规则源：1Hosts (Lite)、AdGuard Base filter、AdGuard Base filter、AdGuard DNS filter、AdRules DNS List、Hblock、NEO DEV HOST、OISD Basic、1024 hosts、ad-wars hosts、StevenBlack hosts、xinggsf、EasyList、Easylist China、EasyPrivacy、CJX's Annoyance List、SmartTV Blocklist、AWAvenue Ads Rule、jiekouAD。\n")
            f.write("! Homepage: https://github.com/217heidai/adblockfilters\n")
            f.write("! Source: https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt\n")
            f.write("! Version: %s\n"%(time.strftime("%Y%m%d%H%M%S", time.localtime())))
            f.write("! Last modified: %s\n"%(time.strftime("%Y/%m/%d %H:%M:%S", time.localtime())))
            f.write("! Blocked domains: %s\n"%(len(blockList)))
            f.write("! unBlocked domains: %s\n"%(len(unblockList)))
            f.write("!\n")
            for fiter in blockList:
                f.write("||%s^\n"%(fiter))
            for fiter in unblockList:
                f.write("@@||%s^\n"%(fiter))
        
        logger.info("adblock dns: block=%d, unblock=%d"%(len(blockList), len(unblockList)))
        return set(blockList), set(unblockList), blockSet_all | unblockSet_all

    # 生成 filter 规则文件
    def __generateFilter(self, filterDict:Dict[str,str], blockSet:Set[str], unblockSet:Set[str], blackSet:Set[str], whiteSet:Set[str], fileName:str):
        logger.info("generate adblock filters...")

        filterList = list(set(filterDict) - whiteSet) # 剔除白名单
        filterList.sort() # 排序
        # 与 adblockdns 去重
        filterList_var = []
        filterList_final = []
        domainSet = set()
        for filter in filterList:
            if filter.startswith('#%#var'):
                filterList_var.append(filter)
                continue
            domain = filterDict[filter]
            if domain:
                domainSet.add(domain)
                if domain in blackSet: # 剔除黑名单
                    continue
                if filter.startswith('||') and domain in blockSet: # 剔除 adblockdns 已拦截
                    continue
                if filter.startswith('@@||') and domain in unblockSet: # 剔除 adblockdns 已放行
                    continue
            filterList_final.append(filter)

        if os.path.exists(fileName):
            os.remove(fileName)
        
        with open(fileName, 'a') as f:
            f.write("!\n")
            f.write("! Title: AdBlock Filter\n")
            f.write("! Description: 适用于AdGuard的去广告合并规则，每8个小时更新一次。规则源：1Hosts (Lite)、AdGuard Base filter、AdGuard Base filter、AdGuard DNS filter、AdRules DNS List、Hblock、NEO DEV HOST、OISD Basic、1024 hosts、ad-wars hosts、StevenBlack hosts、xinggsf、EasyList、Easylist China、EasyPrivacy、CJX's Annoyance List、SmartTV Blocklist、AWAvenue Ads Rule、jiekouAD。\n")
            f.write("! Homepage: https://github.com/217heidai/adblockfilters\n")
            f.write("! Source: https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilters.txt\n")
            f.write("! Version: %s\n"%(time.strftime("%Y%m%d%H%M%S", time.localtime())))
            f.write("! Last modified: %s\n"%(time.strftime("%Y/%m/%d %H:%M:%S", time.localtime())))
            f.write("! Blocked Filters: %s\n"%(len(filterList_final)))
            f.write("!\n")
            for fiter in filterList_var:
                f.write("%s\n"%(fiter))
            for fiter in filterList_final:
                f.write("%s\n"%(fiter))

        logger.info("adblock filters: %d[%d]"%(len(filterList_final), len(filterList)))
        return domainSet

    # 生成用于域名连通性检测的全域名清单
    def __generateDomainList(self, domainSet, fileName:str):
        logger.info("generate domain backup...")
        if os.path.exists(fileName):
            os.remove(fileName)

        with open(fileName, 'a') as f:
            for domain in domainSet:
                f.write("%s\n"%(domain))
        
        logger.info("domain backup: %d"%(len(domainSet)))

    def generate(self):
        # 提取规则
        blockDict,unblockDict,filterDict = self.__getFilters()
        # 提取黑名单、白名单
        blackSet = self.__getBlackList(self.path + "/black.txt")
        whiteSet = self.__getWhiteList(self.path + "/white.txt")
        # 生成合并规则
        blockSet, unblockSet, domainSet_dns = self.__generateDNS(blockDict, unblockDict, blackSet, whiteSet, self.path + "/adblockdns.txt")
        domainSet_filter = self.__generateFilter(filterDict, blockSet, unblockSet, blackSet, whiteSet, self.path + "/adblockfilters.txt")
        # 生成用于域名连通性检测的全域名清单
        self.__generateDomainList(domainSet_dns | domainSet_filter, self.path + "/domain.txt")