import os
import asyncio
from typing import List,Tuple

import httpx
from loguru import logger

class RefreshCDN(object):
    def __init__(self):
        self.pwd = os.getcwd() + '/rules'
        self.blockList = [
            "black.txt",
            "china.txt",
            "direct.txt",
            "domain.txt",
            "ipv4_china.txt",
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
    
        async def _refresh_all():
            tasks = [self.__refresh(rule) for rule in ruleList]
            await asyncio.gather(*tasks)
        
        asyncio.run(_refresh_all())

if __name__ == '__main__':
    cdn = RefreshCDN()
    cdn.refresh()