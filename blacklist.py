import os
import sys
import subprocess as sp
import asyncio

from dns.asyncresolver import Resolver as DNSResolver
from tcping import Ping

from resolver import Resolver

class BlackList(object):
    def __init__(self):
        self.__blacklistFile = os.getcwd() + "/rules/black.txt"
        self.__domainlistFile = os.getcwd() + "/rules/adblockdns.backup"
        self.__maxTask = 500

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
            isAvailable = True
            if domain.rfind(":") > 0: # 兼容 host:port格式
                offset = domain.rfind(":")
                host = domain[ : offset]
                port = int(domain[offset + 1 : ])
            if port:
                try:
                    _, writer = await asyncio.open_connection(host, port)
                    writer.close()
                    await writer.wait_closed()
                    isAvailable = True
                except Exception as e:
                    print("%s[%s]" % (domain, e if e else "Connect failed"))
                    isAvailable = False
            else:
                try:
                    query_object = await dnsresolver.resolve(qname=host, rdtype="A")
                    #query_item = query_object.response.answer[0]
                    #for item in query_item:
                    #    print('{}: {}'.format(host, item))
                    #    break
                    isAvailable = True
                except Exception as e:
                    print("%s[%s]" % (domain, e if e else "Resolver failed"))
                    isAvailable = False
            return domain, isAvailable

    def GenerateBlackList(self, fileName, blackList):
        try:
            if os.path.exists(self.__blacklistFile):
                os.remove(self.__blacklistFile)
            
            with open(fileName, "a") as f:
                for domain in blackList:
                    f.write("%s\n"%(domain))
        except Exception as e:
            print("%s.%s: %s" % (self.__class__.__name__, sys._getframe().f_code.co_name, e))

    def TestDomain(self, domainList, nameservers):
        # 异步检测
        dnsresolver = DNSResolver()
        dnsresolver.nameservers = nameservers
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
        blackDict = {}
        for task in taskList:
            domain, isAvailable = task.result()
            blackDict[domain] = isAvailable
        return blackDict

    def Create(self):
        try:
            domainList = self.GenerateDomainList()
            total = len(domainList)
            if total < 1:
                return
            #domainList = domainList[:self.__maxTask]

            blackDict_cn = self.TestDomain(domainList, ["223.5.5.5", "1.12.12.12", "114.114.114.114"]) # 国内域名解析结果
            blackDict_os = self.TestDomain(domainList, ["8.8.8.8", "1.1.1.1", "9.9.9.11"]) # 国外域名解析结果

            blackList = []
            for domain in domainList:
                if not blackDict_cn.get(domain, True) and not blackDict_os.get(domain, True):
                    blackList.append(domain)

            if len(blackList):
                self.GenerateBlackList(self.__blacklistFile, blackList)
        except Exception as e:
            print("%s.%s: %s" % (self.__class__.__name__, sys._getframe().f_code.co_name, e))

if __name__ == "__main__":
    blackList = BlackList()
    blackList.Create()