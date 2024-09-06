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
        # 启动异步循环
        loop = asyncio.get_event_loop()
        # 添加异步任务
        taskList = []
        for rule in self.ruleList:
            logger.info("updating %s..."%(rule.name))
            task = asyncio.ensure_future(self.__Download(rule, path))
            taskList.append(task)
        # 等待异步任务结束
        loop.run_until_complete(asyncio.wait(taskList))
        # 获取异步任务结果
        for task in taskList:
            new:Rule = task.result()
            for rule in self.ruleList:
                if new.name == rule.name:
                    rule.latest = new.latest
                    rule.update = new.update
                    if rule.update:
                        self.isNeedUpdate = rule.update
                    break
        return self.isNeedUpdate, self.ruleList

    def __CalcFileSha256(self, filename):
        with open(filename, "rb") as f:
            sha256obj = hashlib.sha256()
            sha256obj.update(f.read())
            hash_value = sha256obj.hexdigest()
            return hash_value
        
    def __isConfigFile(self, filename):
        filestats = os.stat(filename)
        if filestats.st_size < 1024 * 4:
            return False
        return True

    async def __Download(self, rule:Rule, path:str) -> Rule:
        fileName = path + "/" + rule.filename
        fileName_download = fileName + '.download'
        try:
            if os.path.exists(fileName_download):
                os.remove(fileName_download)

            async with httpx.AsyncClient() as client:
                response = await client.get(rule.url)
                response.raise_for_status()
                with open(fileName_download,'wb') as f:
                    f.write(response.content)
            
            if not self.__isConfigFile(fileName_download):
                raise Exception("not rule file")

            if os.path.exists(fileName):
                sha256Old = self.__CalcFileSha256(fileName)
                sha256New = self.__CalcFileSha256(fileName_download)
                if sha256New != sha256Old:
                    rule.update = True
                os.remove(fileName)
            else:
                rule.update = True

            os.rename(fileName_download, fileName)
        except Exception as e:
            logger.error(f'%s download failed: %s' % (rule.name, e))
        finally:
            if rule.update:
                rule.latest = time.strftime("%Y/%m/%d", time.localtime())
            logger.info("%s: latest=%s, update=%s"%(rule.name,rule.latest,rule.update))
            return rule