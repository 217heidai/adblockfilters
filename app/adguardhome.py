import os
from typing import List, Set, Dict

from loguru import logger

from app.base import APPBase

class AdGuardHome(APPBase):
    def __init__(self, blockList:List[str], unblockList:List[str], filterDict:Dict[str,str], filterList:List[str], filterList_var:List[str], ChinaSet:Set[str], fileName:str, sourceRule:str):
        super(AdGuardHome, self).__init__(blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, fileName, sourceRule)

    def generate(self, isLite=False):
        try:
            if isLite:
                logger.info("generate adblock AdGuardHome Lite...")
                fileName = self.fileNameLite
                blockList = self.blockListLite
                unblockList = self.unblockListLite
            else:
                logger.info("generate adblock AdGuardHome...")
                fileName = self.fileName
                blockList = self.blockList
                unblockList = self.unblockList
            
            if os.path.exists(fileName):
                os.remove(fileName)
            
            # 生成规则文件
            with open(fileName, 'a') as f:
                f.write("!\n")
                if isLite:
                    f.write("! Title: AdBlock DNS Lite\n")
                    f.write("! Description: 适用于 AdGuard、AdGuardHome 的去广告合并规则，每 8 个小时更新一次。规则源：%s。Lite 版仅针对国内域名拦截。\n"%(self.sourceRule))
                else:
                    f.write("! Title: AdBlock DNS\n")
                    f.write("! Description: 适用于 AdGuard、AdGuardHome 的去广告合并规则，每 8 个小时更新一次。规则源：%s。\n"%(self.sourceRule))
                f.write("! Homepage: %s\n"%(self.homepage))
                f.write("! Source: %s/%s\n"%(self.source, os.path.basename(fileName)))
                f.write("! Version: %s\n"%(self.version))
                f.write("! Last modified: %s\n"%(self.time))
                f.write("! Blocked domains: %s\n"%(len(blockList)))
                f.write("! unBlocked domains: %s\n"%(len(unblockList)))
                f.write("!\n")
                for domain in blockList:
                    f.write("||%s^\n"%(domain))
                for domain in unblockList:
                    f.write("@@||%s^\n"%(domain))
            
            if isLite:
                logger.info("adblock AdGuardHome Lite: block=%d, unblock=%d"%(len(blockList), len(unblockList)))
            else:
                logger.info("adblock AdGuardHome: block=%d, unblock=%d"%(len(blockList), len(unblockList)))
        except Exception as e:
            logger.error("%s"%(e))