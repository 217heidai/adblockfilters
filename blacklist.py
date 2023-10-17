import os
import sys
import subprocess as sp
from concurrent.futures import ThreadPoolExecutor,as_completed

from tcping import Ping

from resolver import Resolver

class BlackList(object):
    def __init__(self):
        self.__blacklistFile = os.getcwd() + "/rules/black.txt"
        self.__domainlistFile = os.getcwd() + "/rules/adblockdns.backup"
        self.__maxTask = 1000
        self.__thread_pool = ThreadPoolExecutor(max_workers=self.__maxTask)

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
            
            self.GenerateBlackList(self.__blacklistFile, blackList)
        except Exception as e:
            print("%s.%s: %s" % (self.__class__.__name__, sys._getframe().f_code.co_name, e))

if __name__ == '__main__':
    blackList = BlackList()
    blackList.Create()