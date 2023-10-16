import os
import sys
import subprocess as sp
from queue import Queue
from concurrent.futures import ThreadPoolExecutor,as_completed

from tcping import Ping

from resolver import Resolver

class BlackList(object):
    def __init__(self):
        self.__blacklistFile = os.getcwd() + "/rules/black.txt"
        self.__domainlistFile = os.getcwd() + "/rules/adblockdns.txt"
        self.__queue = Queue()
        self.__maxTask = 100
        self.__thread_pool = ThreadPoolExecutor(max_workers=self.__maxTask)

    def GenerateDNSList(self):
        try:
            resolver = Resolver(self.__domainlistFile)
            blockDict,unblockDict,_ = resolver.Resolve("dns")
            for fld,subdomainList in blockDict.items():
                for subdomain in subdomainList:
                    domain = fld
                    if len(subdomain):
                        domain = subdomain +"." + domain
                    self.__queue.put(domain)
                    #print(sys._getframe().f_code.co_name, domain)
            for fld,subdomainList in unblockDict.items():
                for subdomain in subdomainList:
                    domain = fld
                    if len(subdomain):
                        domain = subdomain +"." + domain
                    self.__queue.put(domain)
                    #print(sys._getframe().f_code.co_name, domain)
        except Exception as e:
            print("%s.%s: %s" % (self.__class__.__name__, sys._getframe().f_code.co_name, e))

    def ping(self):
        try:
            blackList = []
            while not self.__queue.empty():
                domain = self.__queue.get()
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
            self.GenerateDNSList()
            taskList = []
            for i in range(self.__maxTask):
                taskList.append(self.__thread_pool.submit(self.ping))
            
            # 等待所有线程结束
            blackList = []
            for future in as_completed(taskList):
                tmpList = future.result()
                blackList += tmpList

            self.GenerateBlackList(self.__blacklistFile, blackList)
        except Exception as e:
            print("%s.%s: %s" % (self.__class__.__name__, sys._getframe().f_code.co_name, e))

if __name__ == '__main__':
    blackList = BlackList()
    blackList.Create()