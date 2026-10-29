import os
import time
import hashlib
import asyncio
from typing import List,Tuple

import httpx
from loguru import logger

from readme import Rule

# 上游规则更新
class Updater(object):
    def __init__(self, ruleList:List[Rule]):
        self.ruleList = ruleList
        self.isNeedUpdate = False

    def update(self, path:str) -> Tuple[bool,List[Rule]]:
        async def _update():
            # 并发执行所有下载任务，并直接拿到结果
            tasks = [self.__Download(rule, path) for rule in self.ruleList]
            results = await asyncio.gather(*tasks)

            # 更新规则状态
            for new in results:
                for rule in self.ruleList:
                    if new.name == rule.name:
                        rule.latest = new.latest
                        rule.update = new.update
                        if rule.update:
                            self.isNeedUpdate = True   # 只要有一个需要更新就标记
                        break
            return self.isNeedUpdate, self.ruleList

        return asyncio.run(_update())

    def __CalcFileSha256(self, filename):
        with open(filename, "rb") as f:
            sha256obj = hashlib.sha256()
            sha256obj.update(f.read())
            hash_value = sha256obj.hexdigest()
            return hash_value

    async def __Download(self, rule:Rule, path:str) -> Rule:
        fileName = path + "/" + rule.filename
        fileName_download = fileName + '.download'
        try:
            if os.path.exists(fileName_download):
                os.remove(fileName_download)

            async with httpx.AsyncClient() as client:
                response = await client.get(rule.url)
                response.raise_for_status()
                contentType = response.headers.get("Content-Type")
                if contentType.find("text/plain") < 0:
                    raise Exception("Content-Type[%s] error"%(contentType))
                with open(fileName_download,'wb') as f:
                    f.write(response.content)

            if os.path.exists(fileName):
                sha256Old = self.__CalcFileSha256(fileName)
                sha256New = self.__CalcFileSha256(fileName_download)
                if sha256New != sha256Old:
                    rule.update = True
                os.remove(fileName)
            else:
                rule.update = True

            os.rename(fileName_download, fileName)

            if rule.update:
                rule.latest = time.strftime("%Y/%m/%d", time.localtime())
            logger.info("%s: latest=%s, update=%s"%(rule.name,rule.latest,rule.update))
            return rule
        except Exception as e:
            logger.error(f'%s download failed: %s' % (rule.name, e))
            return rule