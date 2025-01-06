import time
from typing import List, Set, Dict
from abc import ABC, abstractmethod

from loguru import logger


class APPBase(ABC):
    def __init__(self, blockList:List[str], unblockList:List[str], filterDict:Dict[str,str], filterList:List[str], filterList_var:List[str], ChinaSet:Set[str], fileName:str, sourceRule:str):
        self.homepage:str = "https://github.com/217heidai/adblockfilters"
        self.source:str = "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules"
        self.version:str = "%s"%(time.strftime("%Y%m%d%H%M%S", time.localtime()))
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
        except Exception as e:
            logger.error("%s"%(e))
        finally:
            return liteList

    def __generateFilterLiteList(self, filterDict:Dict[str,str], filterList:List[str], ChinaSet:Set[str]):
        liteList = []
        try:
            for filter in filterList:
                domain = filterDict[filter]
                if domain:
                    if domain in ChinaSet:
                        liteList.append(filter)
                else:
                    liteList.append(filter)
        except Exception as e:
            logger.error("%s"%(e))
        finally:
            return liteList

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