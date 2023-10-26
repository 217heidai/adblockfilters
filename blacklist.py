import os
import sys
import subprocess as sp
from concurrent.futures import ThreadPoolExecutor,as_completed
import asyncio

import httpx
from tcping import Ping

from resolver import Resolver

class BlackList(object):
    def __init__(self):
        self.__blacklistFile = os.getcwd() + "/rules/black.txt"
        self.__domainlistFile = os.getcwd() + "/rules/adblockdns.backup"
        self.__maxTask = 500
        self.__thread_pool = ThreadPoolExecutor(max_workers=self.__maxTask)
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0"}
        self.__client = httpx.AsyncClient(headers=headers)

    def GenerateDomainList(self):
        try:
            domainList = []
            resolver = Resolver(self.__domainlistFile)
            blockDict,unblockDict,_ = resolver.Resolve("dns")
            for fld,subdomainList in blockDict.items():
                for subdomain in subdomainList:
                    domain = fld
                    if len(subdomain):
                        domain = subdomain +"." + domain
                    domainList.append(domain)
                    #print(sys._getframe().f_code.co_name, domain)
            for fld,subdomainList in unblockDict.items():
                for subdomain in subdomainList:
                    domain = fld
                    if len(subdomain):
                        domain = subdomain +"." + domain
                    domainList.append(domain)
                    #print(sys._getframe().f_code.co_name, domain)
        except Exception as e:
            print("%s.%s: %s" % (self.__class__.__name__, sys._getframe().f_code.co_name, e))
        finally:
            return domainList

    def ping(self, domainList):
        try:
            blackList = []
            for domain in domainList:
                if domain.rfind(":") > 0: # 兼容 IP:port格式
                    domain = domain[:domain.rfind(":")]
                res = sp.call(['tcping', '-c', '3', '-t', '1', domain], stdout=sp.DEVNULL, stderr=sp.DEVNULL)
                if res != 0:
                    #print(sys._getframe().f_code.co_name, domain, True if res == 0 else False)
                    blackList.append(domain)
        except Exception as e:
            print("%s.%s: %s" % (self.__class__.__name__, sys._getframe().f_code.co_name, e))
        finally:
            return blackList
    
    async def pingx(self, domain):
        try:
            url = "http://%s"%(domain)
            response1 = await self.__client.get(url)
            #print("1[%s]: %s"%(url, response1.status_code))
        except Exception as e:
            #print("2[%s]: %s"%(url, e))
            response1 = None
        try:
            url = "https://%s"%(domain)
            response2 = await self.__client.get(url)
            #print("3[%s]: %s"%(url, response1.status_code))
        except Exception as e:
            #print("4[%s]: %s"%(url, e))
            response2 = None
        
        if not response1 and not response2:
            #print("5[%s]: Fail"%(domain))
            return domain
        else:
            return None

    def GenerateBlackList(self, fileName, blackList):
        try:
            if os.path.exists(self.__blacklistFile):
                os.remove(self.__blacklistFile)
            
            with open(fileName, 'a') as f:
                for domain in blackList:
                    f.write("%s\n"%(domain))
        except Exception as e:
            print("%s.%s: %s" % (self.__class__.__name__, sys._getframe().f_code.co_name, e))

    def Create(self):
        try:
            domainList = self.GenerateDomainList()
            total = len(domainList)
            if total < 1:
                return
            
            # 启动异步循环
            loop = asyncio.get_event_loop()
            # 添加异步任务
            taskList = []
            for domain in domainList:
                task = asyncio.ensure_future(self.pingx(domain))
                taskList.append(task)
            # 等待异步任务结束
            loop.run_until_complete(asyncio.wait(taskList))
            # 获取异步任务结果
            blackList = []
            for task in taskList:
                domain = task.result()
                if domain:
                   blackList.append(domain) 
            '''多线程
            count = (total + self.__maxTask - 1) // self.__maxTask
            taskList = []
            for i in range(self.__maxTask - 1):
                start = i * count
                end = start + count
                taskList.append(self.__thread_pool.submit(self.ping, domainList[start : end]))
            taskList.append(self.__thread_pool.submit(self.ping, domainList[i * count :]))
            
            # 等待所有线程结束
            blackList = []
            for future in as_completed(taskList):
                tmpList = future.result()
                blackList += tmpList
            if len(blackList) < 1:
                return
            '''
            
            self.GenerateBlackList(self.__blacklistFile, blackList)
        except Exception as e:
            print("%s.%s: %s" % (self.__class__.__name__, sys._getframe().f_code.co_name, e))

if __name__ == '__main__':
    blackList = BlackList()
    blackList.Create()