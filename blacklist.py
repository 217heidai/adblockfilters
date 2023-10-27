import os
import sys
import subprocess as sp
import asyncio
#from concurrent.futures import ThreadPoolExecutor,as_completed

from dns.asyncresolver import Resolver as DNSResolver
from tcping import Ping

from resolver import Resolver

class BlackList(object):
    def __init__(self):
        self.__blacklistFile = os.getcwd() + "/rules/black.txt"
        self.__domainlistFile = os.getcwd() + "/rules/adblockdns.backup"
        self.__maxTask = 500
        #self.__thread_pool = ThreadPoolExecutor(max_workers=self.__maxTask)

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
                res = sp.call(["tcping", "-c", "3", "-t", "1", domain], stdout=sp.DEVNULL, stderr=sp.DEVNULL)
                if res != 0:
                    #print(sys._getframe().f_code.co_name, domain, True if res == 0 else False)
                    blackList.append(domain)
        except Exception as e:
            print("%s.%s: %s" % (self.__class__.__name__, sys._getframe().f_code.co_name, e))
        finally:
            return blackList
    
    async def pingx(self, dnsresolver, domain, semaphore):
        async with semaphore: # 限制并发数，超过系统限制后会报错Too many open files
            host = domain
            port = None
            if domain.rfind(":") > 0: # 兼容 host:port格式
                offset = domain.rfind(":")
                host = domain[ : offset]
                port = int(domain[offset + 1 : ])
            if port:
                try:
                    _, writer = await asyncio.open_connection(host, port)
                    writer.close()
                    await writer.wait_closed()
                    return None
                except Exception as e:
                    print("%s[%s]" % (domain, e if e else "Connect failed"))
                    return domain
            else:
                try:
                    query_object = await dnsresolver.resolve(qname=host, rdtype="A")
                    #query_item = query_object.response.answer[0]
                    #for item in query_item:
                    #    print('{}: {}'.format(host, item))
                    #    break
                    return None
                except Exception as e:
                    print("%s[%s]" % (domain, e if e else "Resolver failed"))
                    return domain

    def GenerateBlackList(self, fileName, blackList):
        try:
            if os.path.exists(self.__blacklistFile):
                os.remove(self.__blacklistFile)
            
            with open(fileName, "a") as f:
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
            # 异步检测
            #domainList = domainList[:self.__maxTask]
            dnsresolver = DNSResolver()
            dnsresolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.11", "223.5.5.5", "1.12.12.12"] # 设置5组DNS服务器，3组国外，2组国内
            #dnsresolver.nameservers = ["223.5.5.5", "1.12.12.12", "114.114.114.114"]
            # 启动异步循环
            loop = asyncio.get_event_loop()
            semaphore = asyncio.Semaphore(self.__maxTask) # 限制并发量为500
            # 添加异步任务
            taskList = []
            for domain in domainList:
                task = asyncio.ensure_future(self.pingx(dnsresolver, domain, semaphore))
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

if __name__ == "__main__":
    blackList = BlackList()
    blackList.Create()