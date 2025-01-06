import os
import asyncio
from typing import List,Tuple

import httpx
from loguru import logger

class RefreshCDN(object):
    def __init__(self):
        self.pwd = os.getcwd() + '/rules'
        self.blockList = [
            "apple-cn.txt",
            "black.txt",
            "china.txt",
            "CN-ip-cidr.txt",
            "direct-list.txt",
            "domain.txt",
            "google-cn.txt",
            "myblock.txt",
            "white.txt"
        ]

    def __getRuleList(self, pwd:str) -> List[str]:
        L = []
        cmd = 'cd %s && ls' %(pwd)
        process = os.popen(cmd)
        output = process.read()
        process.close()
        result = output.split("\n")
        for fileName in result:
            if os.path.isfile("%s/%s"%(pwd, fileName)) and fileName not in self.blockList:
                L.append(fileName)
        return L

    async def __refresh(self, fileName):
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get("https://purge.jsdelivr.net/gh/217heidai/adblockfilters@main/rules/%s"%(fileName))
                response.raise_for_status()
                status = response.json().get("status", "")
                logger.info(f'%s refresh status: %s' % (fileName, status))
        except Exception as e:
            logger.error(f'%s refresh failed: %s' % (fileName, e))

    def refresh(self):
        ruleList = self.__getRuleList(self.pwd)
        # 启动异步循环
        loop = asyncio.get_event_loop()
        # 添加异步任务
        taskList = []
        for rule in ruleList:
            logger.info("refresh %s..."%(rule))
            task = asyncio.ensure_future(self.__refresh(rule))
            taskList.append(task)
        # 等待异步任务结束
        loop.run_until_complete(asyncio.wait(taskList))

if __name__ == '__main__':
    cdn = RefreshCDN()
    cdn.refresh()