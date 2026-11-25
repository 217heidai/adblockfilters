import os
import re
import time
from functools import lru_cache
from typing import List, Set, Dict
from abc import ABC, abstractmethod

from tld import get_tld

from loguru import logger


@lru_cache(maxsize=None)
def _cached_get_tld(address:str):
    # 同一域名在 full/Lite 两遍生成里各算一次，缓存后第二遍基本免费；
    # 进程内 TLD 表不变（启动时 update_tld_names 只跑一次），缓存安全
    return get_tld(address, fix_protocol=True, as_object=True)


class APPBase(ABC):
    def __init__(self, blockList:List[str], unblockList:List[str], filterDict:Dict[str,str], filterList:List[str], filterList_var:List[str], ChinaSet:Set[str], fileName:str, sourceRule:str):
        self.homepage:str = "https://github.com/217heidai/adblockfilters"
        self.source:str = "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules"
        self.version:str = "%s"%(time.strftime("%Y%m%d%H%M%S", time.localtime()))
        _sha = os.environ.get("GITHUB_SHA", "")[:7]
        if _sha:
            self.version += "-%s"%(_sha)
        self.time:str = "%s"%(time.strftime("%Y/%m/%d %H:%M:%S", time.localtime()))
        self.blockList:List[str] = blockList
        self.unblockList:List[str] = unblockList
        self.filterDict:Dict[str,str] = filterDict
        self.filterList:List[str] = filterList
        self.filterList_var:List[str] = filterList_var
        self.ChinaSet:Set[str] = ChinaSet
        self.fileName:str = fileName
        self.sourceRule:str = sourceRule
        self.blockListLite:List[str] = self.__generateDomainLiteList(self.blockList, self.ChinaSet)
        self.unblockListLite:List[str] = self.__generateDomainLiteList(self.unblockList, self.ChinaSet)
        self.filterListLite:List[str] = self.__generateFilterLiteList(self.filterDict, self.filterList, self.ChinaSet)
        self.fileNameLite:str = fileName[:self.fileName.rfind(".")] + "lite" + fileName[self.fileName.rfind("."):]
    
    def __generateDomainLiteList(self, domainList:List[str], ChinaSet:Set[str]):
        liteList = []
        try:
            for domain in domainList:
                if domain in ChinaSet:
                    liteList.append(domain)
            return liteList
        except Exception as e:
            logger.error("%s"%(e))
            return liteList

    def __generateFilterLiteList(self, filterDict:Dict[str,str], filterList:List[str], ChinaSet:Set[str]):
        liteList = []
        try:
            for filter in filterList:
                domain = filterDict[filter]
                if domain:
                    if domain in ChinaSet:
                        liteList.append(filter)
                elif self.__isChinaFilter(filter, ChinaSet):
                    liteList.append(filter)
            return liteList
        except Exception as e:
            logger.error("%s"%(e))
            return liteList

    # 通用 $ 规则无域名：解析 domain= 列表，只有含国内域（或不限域）才进 Lite
    def __isChinaFilter(self, filter:str, ChinaSet:Set[str]) -> bool:
        m = re.search(r'domain=([^,]+)', filter)
        if not m:
            return True  # 不限域，无法证明是国外规则，保留
        domains = [d for d in m.group(1).split('|') if not d.startswith('~')]
        if not domains:
            return True  # 全是排除项，规则适用范围不限于所列域名，保留
        return any(self.__isChinaDomain(d, ChinaSet) for d in domains)

    def __isChinaDomain(self, domain:str, ChinaSet:Set[str]) -> bool:
        labels = domain.split('.')
        for i in range(len(labels)):
            if '.'.join(labels[i:]) in ChinaSet:
                return True
        return False

    @abstractmethod
    def generate(self, isLite=False):
        pass

    def generateAll(self):
        try:
            if len(self.blockList):
                self.generate()

            if len(self.blockListLite):
                self.generate(isLite=True)
        except Exception as e:
            logger.error("%s"%(e))
    
    def isDomain(self, address:str) -> bool:
        try:
            _cached_get_tld(address)
            return True
        except Exception as e:
            logger.error("%s"%(e))
            return False
