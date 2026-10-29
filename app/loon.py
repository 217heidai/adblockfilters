import os
from typing import List, Set, Dict

from loguru import logger

from app.base import APPBase

class Loon(APPBase):
    def __init__(self, blockList:List[str], unblockList:List[str], filterDict:Dict[str,str], filterList:List[str], filterList_var:List[str], ChinaSet:Set[str], fileName:str, sourceRule:str):
        super(Loon, self).__init__(blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, fileName, sourceRule)

    def generate(self, isLite=False):
        try:
            if isLite:
                logger.info("generate adblock Loon Lite...")
                fileName = self.fileNameLite
                blockList = self.blockListLite
            else:
                logger.info("generate adblock Loon...")
                fileName = self.fileName
                blockList = self.blockList

            if os.path.exists(fileName):
                os.remove(fileName)

            # 生成规则文件
            with open(fileName, 'a') as f:
                f.write("#\n")
                if isLite:
                    f.write("#!name=AdBlock Loon Lite\n")
                    f.write("#!desc=适用于 Loon 的去广告合并规则，每 8 个小时更新一次。规则源：%s。Lite 版仅针对国内域名拦截。\n"%(self.sourceRule))
                else:
                    f.write("#!name=AdBlock Loon\n")
                    f.write("#!desc=适用于 Loon 的去广告合并规则，每 8 个小时更新一次。规则源：%s。\n"%(self.sourceRule))
                f.write("#!homepage=%s\n"%(self.homepage))
                f.write("#!raw-url=%s/%s\n"%(self.source, os.path.basename(fileName)))
                f.write("#!tag=AdBlock, 217heidai\n")
                f.write("#!system=iOS, iPadOS\n")
                f.write("#!system_version=\n")
                f.write("#!loon_version=\n")
                f.write("#!date=%s\n"%(self.time))
                f.write("#!support=%s\n"%(len(blockList)))
                f.write("#!proxy-select=REJECT\n")
                f.write("#\n")
                for domain in blockList:
                    f.write("DOMAIN-SUFFIX,%s\n"%(domain))

            if isLite:
                logger.info("adblock Loon Lite: block=%d"%(len(blockList)))
            else:
                logger.info("adblock Loon: block=%d"%(len(blockList)))
        except Exception as e:
            logger.error("%s"%(e))
