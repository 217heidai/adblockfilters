import os
from typing import List, Set, Dict

from loguru import logger

from app.base import APPBase


class ShadowrocketModule(APPBase):
    def __init__(
        self,
        blockList: List[str],
        unblockList: List[str],
        filterDict: Dict[str, str],
        filterList: List[str],
        filterList_var: List[str],
        ChinaSet: Set[str],
        fileName: str,
        sourceRule: str,
    ):
        super(ShadowrocketModule, self).__init__(
            blockList,
            unblockList,
            filterDict,
            filterList,
            filterList_var,
            ChinaSet,
            fileName,
            sourceRule,
        )

    def generate(self, isLite: bool = False):
        try:
            if isLite:
                logger.info("generate adblock Shadowrocket Module Lite...")
                fileName = self.fileNameLite
                blockList = self.blockListLite
            else:
                logger.info("generate adblock Shadowrocket Module...")
                fileName = self.fileName
                blockList = self.blockList

            if os.path.exists(fileName):
                os.remove(fileName)

            # Shadowrocket sgmodule metadata uses #!key=value
            with open(fileName, "a", encoding="utf-8") as f:
                if isLite:
                    f.write("#!name=AdBlock Shadowrocket Module Lite\n")
                    f.write(
                        "#!desc=每 8 个小时更新一次。规则源：%s。Lite 版仅针对国内域名拦截。\n"
                        % (self.sourceRule)
                    )
                else:
                    f.write("#!name=AdBlock Shadowrocket Module\n")
                    f.write(
                        "#!desc=每 8 个小时更新一次。规则源：%s。\n"
                        % (self.sourceRule)
                    )

                f.write("#!homepage=%s\n" % (self.homepage))
                f.write("#!source=%s/%s\n" % (self.source, os.path.basename(fileName)))
                f.write("#!version=%s\n" % (self.version))
                f.write("#!updated=%s\n" % (self.time))
                f.write("\n")

                f.write("[Rule]\n")
                for domain in blockList:
                    f.write("DOMAIN-SUFFIX,%s,REJECT-DROP\n" % (domain))

            if isLite:
                logger.info("adblock Shadowrocket Module Lite: block=%d" % (len(blockList)))
            else:
                logger.info("adblock Shadowrocket Module: block=%d" % (len(blockList)))
        except Exception as e:
            logger.error("%s" % (e))
