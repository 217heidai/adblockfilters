import os
import sys
import asyncio

from dns.asyncresolver import Resolver as DNSResolver

class BlackList(object):
    def __init__(self):
        self.__blacklistFile = os.getcwd() + "/rules/black.txt"
        self.__domainlistFile = os.getcwd() + "/rules/adblockdns.backup"
        self.__maxTask = 500

    def GenerateDomainList(self):
        domainList = []
        try:
            if os.path.exists(self.__domainlistFile):
                with open(self.__domainlistFile, 'r') as f:
                    tmp = f.readlines()
                    domainList = list(map(lambda x: x.replace("\n", ""), tmp))
        except Exception as e:
            print("%s.%s: %s" % (self.__class__.__name__, sys._getframe().f_code.co_name, e))
        finally:
            return domainList
    
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

    def GenerateBlackList(self, blackList):
        try:
            if os.path.exists(self.__blacklistFile):
                os.remove(self.__blacklistFile)
            
            with open(self.__blacklistFile, "w") as f:
                for domain in blackList:
                    f.write("%s\n"%(domain))
        except Exception as e:
            print("%s.%s: %s" % (self.__class__.__name__, sys._getframe().f_code.co_name, e))

    def TestDomain(self, domainList, nameservers, port=53):
        # 异步检测
        dnsresolver = DNSResolver()
        dnsresolver.nameservers = nameservers
        dnsresolver.port = port
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
            if len(domainList) < 1:
                return

            blackDict = self.TestDomain(domainList, ["127.0.0.1"], 5053) # 使用本地 smartdns 进行域名解析，配置3组国内、3组国际域名解析服务器，提高识别效率

            blackList = []
            for domain in domainList:
                if not blackDict.get(domain, True):
                    blackList.append(domain)

            if len(blackList):
                self.GenerateBlackList(self.__blacklistFile, blackList)
        except Exception as e:
            print("%s.%s: %s" % (self.__class__.__name__, sys._getframe().f_code.co_name, e))

if __name__ == "__main__":
    blackList = BlackList()
    blackList.Create()
