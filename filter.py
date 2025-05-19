import os
import re
from concurrent.futures import ThreadPoolExecutor,as_completed
from typing import List,Dict,Set,Tuple

from loguru import logger
from tld import get_tld

from app import APPBase, AdGuard, AdGuardHome, DNSMasq, Hosts, InviZible, Loon, Mihomo, QuantumultX, Shadowrocket, SingBox, SmartDNS
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
    
    # 获取黑名单，经测试已无法解析的域名
    def __getBlackList(self, fileName:str) -> Set[str]:
        logger.info("resolve black list...")
        blackSet = set()
        if os.path.exists(fileName):
            with open(fileName, 'r') as f:
                blackList = f.readlines()
                blackSet = set(map(lambda x: x.replace("\n", ""), blackList))
        logger.info("black list: %d"%(len(blackSet)))
        return blackSet

    # 获取白名单，收集的误杀规则
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
    
    def __getWhiteDict(self, whiteSet:Set[str]) -> Dict[str,Set[str]]:
        whiteDict = dict()

        for address in whiteSet:
            try:
                res = get_tld(address, fix_protocol=True, as_object=True)
                fld = res.fld
                subdomain = res.subdomain
                if fld not in whiteDict:
                    whiteDict[fld] = {subdomain}
                else:
                    whiteDict[fld] |= {subdomain}
            except Exception as e:
                pass
        
        return whiteDict
    
    # 获取 China domain 清单，国内域名
    def __getChinaList(self, fileName:str) -> Set[str]:
        logger.info("resolve China list...")
        ChinaSet = set()
        if os.path.exists(fileName):
            with open(fileName, 'r') as f:
                ChinaList = f.readlines()
                ChinaSet = set(map(lambda x: x.replace("\n", ""), ChinaList))
        logger.info("China list: %d"%(len(ChinaSet)))
        return ChinaSet
    
    # 去重、排序
    def __domainSort(self, domainDict:Dict[str, Set[str]], blackSet:Set[str], whiteDict:Dict[str,Set[str]]) -> Tuple[List[str], Set[str]]:
        def repetition(l): # 短域名已被拦截，则干掉所有长域名。如'a.example'、'b.example'、'example'，则只保留'example'
            l = sorted(l, key = lambda item:len(item), reverse=False) # 按从短到长排序
            if len(l) < 2:
                return l
            if l[0] == '':
                return l[:1]
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
            subdomainList_origin = list(domainDict[fld] - whiteDict.get(fld, set())) # 去除需要保留的白名单域名
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

    def __filterSort(self, filterDict:Dict[str,str], blockSet:Set[str], unblockSet:Set[str], blackSet:Set[str], whiteSet:Set[str]) -> Tuple[list[str], Set[str]]:
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
        
        return filterList_var, filterList_final, domainSet_all

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
        # 从上游规则中提取规则
        blockDict,unblockDict,filterDict = self.__getFilters()

        # 提取黑名单、白名单、China domain
        blackSet = self.__getBlackList(self.path + "/black.txt")  # 经测试已无法解析的域名
        whiteSet = self.__getWhiteList(self.path + "/white.txt")  # 收集的误杀规则
        whiteDict = self.__getWhiteDict(whiteSet)
        ChinaSet = self.__getChinaList(self.path + "/china.txt")  # 国内域名

        # 规则处理：合并、去重、排序、剔除剔除黑名单、剔除白名单
        blockList, blockSet_block = self.__domainSort(blockDict, blackSet, whiteDict)
        unblockList, unblockSet_unblock = self.__domainSort(unblockDict, blackSet, whiteDict)
        filterList_var, filterList, domainSet_filter = self.__filterSort(filterDict, set(blockList), set(unblockList), blackSet, whiteSet)

        # 生成合并规则 AdGuard, AdGuardHome, DNSMasq, InviZible, SmartDNS等
        generaterList:List[APPBase] = [
            AdGuard     (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.path + "/adblockfilters.txt",   sourceRule),
            AdGuardHome (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.path + "/adblockdns.txt",       sourceRule),
            DNSMasq     (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.path + "/adblockdnsmasq.txt",   sourceRule),
            Hosts       (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.path + "/adblockhosts.txt",     sourceRule),
            InviZible   (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.path + "/adblockdomain.txt",    sourceRule),
            Loon        (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.path + "/adblockloon.list",      sourceRule),
            Mihomo      (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.path + "/adblockmihomo.yaml",   sourceRule),
            QuantumultX (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.path + "/adblockqx.conf",       sourceRule),
            Shadowrocket(blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.path + "/adblockclash.list",    sourceRule),
            SingBox     (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.path + "/adblocksingbox.json",  sourceRule),
            SmartDNS    (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.path + "/adblocksmartdns.conf", sourceRule),
        ]
        for g in generaterList:
            g.generateAll()
        
        # 生成用于域名连通性检测的全域名清单
        self.__generateDomainBackup(blockSet_block | unblockSet_unblock | domainSet_filter, self.path + "/domain.txt")