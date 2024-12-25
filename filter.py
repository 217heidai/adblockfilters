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
        # 添加收集的补充规则
        rule = Rule("myblock", "dns", "", "")
        taskList.append(thread_pool.submit(resolver.resolveDNS, rule))
        
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
    
    # 获取 China domain 清单
    def __getChinaList(self, fileName:str) -> Set[str]:
        logger.info("resolve China list...")
        ChinaSet = set()
        if os.path.exists(fileName):
            with open(fileName, 'r') as f:
                ChinaList = f.readlines()
                ChinaSet = set(map(lambda x: x.replace("\n", ""), ChinaList))
        logger.info("China list: %d"%(len(ChinaSet)))
        return ChinaSet

    # 生成 dns 规则文件，同时返回全量域名
    def __generateDNS(self, blockDict:Dict[str, Set[str]], unblockDict:Dict[str, Set[str]], blackSet:Set[str], whiteSet:Set[str], fileName:str, sourceRule:str) -> Tuple[list[str], Set[str]]:
        # 去重、排序
        def sort(domainDict:Dict[str, Set[str]], blackSet:Set[str], whiteSet:Set[str]) -> Tuple[List[str], Set[str]]:
            def repetition(l): # 短域名已被拦截，则干掉所有长域名。如'a.example'、'b.example'、'example'，则只保留'example'
                l = sorted(l, key = lambda item:len(item), reverse=False) # 按从短到长排序
                if l[0] == '':
                    return l[:1]
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
            def get_domain(fld, subdomain):
                if len(subdomain) > 0:
                    domain = ("%s.%s")%(subdomain, fld)
                else:
                    domain = ("%s")%(fld)
                return domain
            domanList = []
            domanSet_all = set()
            fldList = list(domainDict.keys())
            fldList.sort() # 排序
            for fld in fldList:
                subdomainList_origin = list(domainDict[fld])
                subdomainList = repetition(subdomainList_origin) # 短域名已被拦截，则干掉所有长域名。如'a.example'、'b.example'、'example'，则只保留'example'
                for subdomain in subdomainList:
                    subdomain_not_black = False
                    for _subdomain in list(set(subdomainList_origin) - set(subdomainList)):
                        if len(subdomain) > 0:
                            if re.match('.*\.%s$'%(subdomain), _subdomain):
                                _domain = get_domain(fld, _subdomain)
                                if _domain not in blackSet:
                                    subdomain_not_black = True
                                    break
                        else:
                            _domain = get_domain(fld, _subdomain)
                            if _domain not in blackSet:
                                subdomain_not_black = True
                                break
                    
                    domain = get_domain(fld, subdomain)
                    if domain not in whiteSet:
                        if domain not in blackSet:
                            domanList.append(domain)
                        else:
                            if subdomain_not_black: # 只要子域名有一个未black，仍然保留
                                domanList.append(domain)

                # 全域名保留，用于后续验证连通性
                for subdomain in subdomainList_origin: 
                    domain = get_domain(fld, subdomain)
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
            f.write("! Description: 适用于 AdGuard 的去广告合并规则，每 8 个小时更新一次。规则源：%s。\n"%(sourceRule))
            f.write("! Homepage: https://github.com/217heidai/adblockfilters\n")
            f.write("! Source: https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt\n")
            f.write("! Version: %s\n"%(time.strftime("%Y%m%d%H%M%S", time.localtime())))
            f.write("! Last modified: %s\n"%(time.strftime("%Y/%m/%d %H:%M:%S", time.localtime())))
            f.write("! Blocked domains: %s\n"%(len(blockList)))
            f.write("! unBlocked domains: %s\n"%(len(unblockList)))
            f.write("!\n")
            for domain in blockList:
                f.write("||%s^\n"%(domain))
            for domain in unblockList:
                f.write("@@||%s^\n"%(domain))
        
        logger.info("adblock dns: block=%d, unblock=%d"%(len(blockList), len(unblockList)))
        return blockList, unblockList, blockSet_all | unblockSet_all

    # 生成 dns 规则文件
    def __generateDNSLite(self, blockList:List[str], unblockList:List[str], ChinaSet:Set[str], fileName:str, sourceRule:str):
        logger.info("generate adblock dns lite...")

        blockList_lite = []
        for domain in blockList:
            if domain in ChinaSet:
                blockList_lite.append(domain)
        
        unblockList_lite = []
        for domain in unblockList:
            if domain in ChinaSet:
                unblockList_lite.append(domain)

        # 生成规则文件
        if os.path.exists(fileName):
            os.remove(fileName)    
        with open(fileName, 'a') as f:
            f.write("!\n")
            f.write("! Title: AdBlock DNS Lite\n")
            f.write("! Description: 适用于 AdGuard 的去广告合并规则，每 8 个小时更新一次。规则源：%s。Lite 版仅针对国内域名拦截。\n"%(sourceRule))
            f.write("! Homepage: https://github.com/217heidai/adblockfilters\n")
            f.write("! Source: https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt\n")
            f.write("! Version: %s\n"%(time.strftime("%Y%m%d%H%M%S", time.localtime())))
            f.write("! Last modified: %s\n"%(time.strftime("%Y/%m/%d %H:%M:%S", time.localtime())))
            f.write("! Blocked domains: %s\n"%(len(blockList_lite)))
            f.write("! unBlocked domains: %s\n"%(len(unblockList_lite)))
            f.write("!\n")
            for domain in blockList_lite:
                f.write("||%s^\n"%(domain))
            for domain in unblockList_lite:
                f.write("@@||%s^\n"%(domain))
        
        logger.info("adblock dns: block=%d, unblock=%d"%(len(blockList_lite), len(unblockList_lite)))

    # 生成 filter 规则文件
    def __generateFilter(self, filterDict:Dict[str,str], blockSet:Set[str], unblockSet:Set[str], blackSet:Set[str], whiteSet:Set[str], fileName:str, sourceRule:str) -> Tuple[list[str], Set[str]]:
        logger.info("generate adblock filters...")

        filterList = list(set(filterDict) - whiteSet) # 剔除白名单
        filterList.sort() # 排序
        # 与 adblockdns 去重
        filterList_var = []
        filterList_final = []
        domainSet_all = set()
        for filter in filterList:
            if filter.startswith('#%#var'):
                filterList_var.append(filter)
                continue
            
            domain = filterDict[filter]
            if domain:
                if domain in blackSet: # 剔除黑名单
                    continue
                try:
                    res = get_tld(domain, fix_protocol=True, as_object=True)
                    fld = res.fld
                except Exception as e:
                    fld = ''
                if filter.startswith('@@'):
                    if domain in unblockSet or fld in unblockSet: # 剔除 adblockdns 已放行
                        continue
                else:
                    if domain in blockSet or fld in blockSet: # 剔除 adblockdns 已拦截
                        continue
                domainSet_all.add(domain)
            
            filterList_final.append(filter)

        if os.path.exists(fileName):
            os.remove(fileName)
        with open(fileName, 'a') as f:
            f.write("!\n")
            f.write("! Title: AdBlock Filter\n")
            f.write("! Description: 适用于 AdGuard 的去广告合并规则，每 8 个小时更新一次。规则源：%s。\n"%(sourceRule))
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
        return filterList_var,filterList_final,domainSet_all

    # 生成 filter 规则文件
    def __generateFilterLite(self, filterDict:Dict[str,str], filterList_var:List[str], filterList_final:List[str], ChinaSet:Set[str], fileName:str, sourceRule:str):
        logger.info("generate adblock filters lite...")

        filterList_lite = []
        for filter in filterList_final:
            domain = filterDict[filter]
            if domain:
                if domain in ChinaSet:
                    filterList_lite.append(filter)
            else:
                filterList_lite.append(filter)

        if os.path.exists(fileName):
            os.remove(fileName)
        with open(fileName, 'a') as f:
            f.write("!\n")
            f.write("! Title: AdBlock Filter Lite\n")
            f.write("! Description: 适用于 AdGuard 的去广告合并规则，每 8 个小时更新一次。规则源：%s。Lite 版仅针对国内域名拦截。\n"%(sourceRule))
            f.write("! Homepage: https://github.com/217heidai/adblockfilters\n")
            f.write("! Source: https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilters.txt\n")
            f.write("! Version: %s\n"%(time.strftime("%Y%m%d%H%M%S", time.localtime())))
            f.write("! Last modified: %s\n"%(time.strftime("%Y/%m/%d %H:%M:%S", time.localtime())))
            f.write("! Blocked Filters: %s\n"%(len(filterList_lite)))
            f.write("!\n")
            for fiter in filterList_var:
                f.write("%s\n"%(fiter))
            for fiter in filterList_lite:
                f.write("%s\n"%(fiter))

        logger.info("adblock filters: %d"%(len(filterList_lite)))

    # 生成纯域名规则
    def __generateDomain(self, blockList:List[str], fileName:str, sourceRule:str):
        logger.info("generate adblock domain...")

        # 生成规则文件
        if os.path.exists(fileName):
            os.remove(fileName)    
        with open(fileName, 'a') as f:
            f.write("!\n")
            f.write("! Title: AdBlock Domain\n")
            f.write("! Description: 适用于 InviZible Pro、personalDNSfilter 的去广告合并规则，每 8 个小时更新一次。规则源：%s。\n"%(sourceRule))
            f.write("! Homepage: https://github.com/217heidai/adblockfilters\n")
            f.write("! Source: https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdomain.txt\n")
            f.write("! Version: %s\n"%(time.strftime("%Y%m%d%H%M%S", time.localtime())))
            f.write("! Last modified: %s\n"%(time.strftime("%Y/%m/%d %H:%M:%S", time.localtime())))
            f.write("! Blocked domains: %s\n"%(len(blockList)))
            f.write("!\n")
            for domain in blockList:
                f.write("%s\n"%(domain))
        
        logger.info("adblock domain: block=%d"%(len(blockList)))

    # 生成纯域名规则
    def __generateDomainLite(self, blockList:List[str], ChinaSet:Set[str], fileName:str, sourceRule:str):
        logger.info("generate adblock domain lite...")

        blockList_lite = []
        for domain in blockList:
            if domain in ChinaSet:
                blockList_lite.append(domain)

        # 生成规则文件
        if os.path.exists(fileName):
            os.remove(fileName)    
        with open(fileName, 'a') as f:
            f.write("!\n")
            f.write("! Title: AdBlock Domain Lite\n")
            f.write("! Description: 适用于 InviZible Pro、personalDNSfilter 的去广告合并规则，每 8 个小时更新一次。规则源：%s。Lite 版仅针对国内域名拦截。\n"%(sourceRule))
            f.write("! Homepage: https://github.com/217heidai/adblockfilters\n")
            f.write("! Source: https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdomainlite.txt\n")
            f.write("! Version: %s\n"%(time.strftime("%Y%m%d%H%M%S", time.localtime())))
            f.write("! Last modified: %s\n"%(time.strftime("%Y/%m/%d %H:%M:%S", time.localtime())))
            f.write("! Blocked domains: %s\n"%(len(blockList_lite)))
            f.write("!\n")
            for domain in blockList_lite:
                f.write("%s\n"%(domain))
        
        logger.info("adblock domain: block=%d"%(len(blockList_lite)))

    # 生成 DNSMasq 规则
    def __generateDNSMasq(self, blockList:List[str], fileName:str, sourceRule:str):
        logger.info("generate adblock DNSMasq...")

        # 生成规则文件
        if os.path.exists(fileName):
            os.remove(fileName)    
        with open(fileName, 'a') as f:
            f.write("#\n")
            f.write("# Title: AdBlock DNSMasq\n")
            f.write("# Description: 适用于 DNSMasq 的去广告合并规则，每 8 个小时更新一次。规则源：%s。\n"%(sourceRule))
            f.write("# Homepage: https://github.com/217heidai/adblockfilters\n")
            f.write("# Source: https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnsmasq.txt\n")
            f.write("# Version: %s\n"%(time.strftime("%Y%m%d%H%M%S", time.localtime())))
            f.write("# Last modified: %s\n"%(time.strftime("%Y/%m/%d %H:%M:%S", time.localtime())))
            f.write("# Blocked domains: %s\n"%(len(blockList)))
            f.write("#\n")
            for domain in blockList:
                f.write("local=/%s/\n"%(domain))
        
        logger.info("adblock DNSMasq: block=%d"%(len(blockList)))

    # 生成 DNSMasq 规则
    def __generateDNSMasqLite(self, blockList:List[str], ChinaSet:Set[str], fileName:str, sourceRule:str):
        logger.info("generate adblock DNSMasq lite...")

        blockList_lite = []
        for domain in blockList:
            if domain in ChinaSet:
                blockList_lite.append(domain)

        # 生成规则文件
        if os.path.exists(fileName):
            os.remove(fileName)    
        with open(fileName, 'a') as f:
            f.write("!\n")
            f.write("# Title: AdBlock DNSMasq Lite\n")
            f.write("# Description: 适用于 DNSMasq 的去广告合并规则，每 8 个小时更新一次。规则源：%s。Lite 版仅针对国内域名拦截。\n"%(sourceRule))
            f.write("! Homepage: https://github.com/217heidai/adblockfilters\n")
            f.write("! Source: https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnsmasqlite.txt\n")
            f.write("! Version: %s\n"%(time.strftime("%Y%m%d%H%M%S", time.localtime())))
            f.write("! Last modified: %s\n"%(time.strftime("%Y/%m/%d %H:%M:%S", time.localtime())))
            f.write("! Blocked domains: %s\n"%(len(blockList_lite)))
            f.write("!\n")
            for domain in blockList_lite:
                f.write("local=/%s/\n"%(domain))
        
        logger.info("adblock DNSMasq: block=%d"%(len(blockList_lite)))

    # 生成用于域名连通性检测的全域名清单
    def __generateDomainBackup(self, domainSet, fileName:str):
        logger.info("generate domain backup...")
        if os.path.exists(fileName):
            os.remove(fileName)

        domainList = list(domainSet)
        domainList.sort() # 排序

        with open(fileName, 'a') as f:
            for domain in domainList:
                f.write("%s\n"%(domain))
        
        logger.info("domain backup: %d"%(len(domainList)))

    def generate(self, sourceRule):
        # 提取规则
        blockDict,unblockDict,filterDict = self.__getFilters()
        # 提取黑名单、白名单、China domain
        blackSet = self.__getBlackList(self.path + "/black.txt")
        whiteSet = self.__getWhiteList(self.path + "/white.txt")
        ChinaSet = self.__getChinaList(self.path + "/china.txt")
        # 生成合并规则
        blockList, unblockList, domainSet_dns = self.__generateDNS(blockDict, unblockDict, blackSet, whiteSet, self.path + "/adblockdns.txt", sourceRule)
        filterList_var, filterList_final, domainSet_filter = self.__generateFilter(filterDict, set(blockList), set(unblockList), blackSet, whiteSet, self.path + "/adblockfilters.txt", sourceRule)
        self.__generateDomain(blockList, self.path + "/adblockdomain.txt", sourceRule)
        self.__generateDNSMasq(blockList, self.path + "/adblockdnsmasq.txt", sourceRule)
        # 生成lite规则
        if len(ChinaSet) > 0:
            self.__generateDNSLite(blockList, unblockList, ChinaSet, self.path + "/adblockdnslite.txt", sourceRule)
            self.__generateFilterLite(filterDict, filterList_var, filterList_final, ChinaSet, self.path + "/adblockfilterslite.txt", sourceRule)
            self.__generateDomainLite(blockList, ChinaSet, self.path + "/adblockdomainlite.txt", sourceRule)
            self.__generateDNSMasqLite(blockList, ChinaSet, self.path + "/adblockdnsmasqlite.txt", sourceRule)
        # 生成用于域名连通性检测的全域名清单
        self.__generateDomainBackup(domainSet_dns | domainSet_filter, self.path + "/domain.txt")