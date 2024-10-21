import os
import asyncio
import re
from concurrent.futures import ThreadPoolExecutor,as_completed

import httpx
import IPy
from tld import get_tld
from loguru import logger
from dns.asyncresolver import Resolver as DNSResolver
from dns.rdatatype import RdataType as DNSRdataType


class ChinaDomian(object):
    def __init__(self, fileName, url):
        self.__fileName = fileName
        self.__url = url
        self.fullSet = set()
        self.domainSet = set()
        self.regexpSet = set()
        self.keywordSet = set()
        self.__update()
        self.__resolve()

    def __update(self):
        try:
            if os.path.exists(self.__fileName):
                os.remove(self.__fileName)
            
            with httpx.Client() as client:
                response = client.get(self.__url)
                response.raise_for_status()
                with open(self.__fileName,'wb') as f:
                    f.write(response.content)
        except Exception as e:
            logger.error("%s"%(e))
    
    def __isDomain(self, address):
        fld, subdomain = '', ''
        try:
            res = get_tld(address, fix_protocol=True, as_object=True) # 确认是否为域名
            fld, subdomain = res.fld, res.subdomain
        except Exception as e:
            logger.error("%s: not domain"%(address))
        finally:
            return fld, subdomain

    def __resolve(self):
        try:
            if not os.path.exists(self.__fileName):
                return
            
            with open(self.__fileName, 'r') as f:
                for line in f:
                    # 去掉换行符
                    line = line.replace('\r', '').replace('\n', '').strip()
                    # 去掉空行
                    if len(line) < 1:
                        continue
                    # 去掉注释
                    if line.startswith('#'):
                        continue
                    if line.find('#') > 0:
                        line = line[:line.find('#')].strip()
                    
                    # regexp
                    if line.startswith('regexp:'):
                        self.regexpSet.add(line[len('regexp:'):])
                        continue
                    
                    # keyword
                    if line.startswith('keyword:'):
                        self.keywordSet.add(line[len('keyword:'):])
                        continue
                    
                    if line.startswith('full:'):
                        domain = line[len('full:'):]
                    elif line.startswith('domain:'):
                        domain = line[len('domain:'):]
                    else:
                        domain = line
                    fld, subdomian = self.__isDomain(domain)
                    if len(fld) > 0:
                        if len(subdomian) > 0:
                            self.fullSet.add(domain)
                        else:
                            self.domainSet.add(domain)
                    else:
                        logger.error("%s: not domain[domain]"%(line))
        except Exception as e:
            logger.error("%s"%(e))


class BlackList(object):
    def __init__(self):
        self.__ChinalistFile = os.getcwd() + "/rules/china.txt"
        self.__blacklistFile = os.getcwd() + "/rules/black.txt"
        self.__domainlistFile = os.getcwd() + "/rules/domain.txt"
        self.__domainlistFile_CN = os.getcwd() + "/rules/direct-list.txt"
        self.__domainlistUrl_CN = "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/refs/heads/release/direct-list.txt"
        self.__domainlistFile_CN_Apple = os.getcwd() + "/rules/apple-cn.txt"
        self.__domainlistUrl_CN_Apple = "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/refs/heads/release/apple-cn.txt"
        self.__domainlistFile_CN_Google = os.getcwd() + "/rules/google-cn.txt"
        self.__domainlistUrl_CN_Google = "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/refs/heads/release/google-cn.txt"
        self.__iplistFile_CN = os.getcwd() + "/rules/CN-ip-cidr.txt"
        self.__iplistUrl_CN = "https://raw.githubusercontent.com/Hackl0us/GeoIP2-CN/refs/heads/release/CN-ip-cidr.txt"
        self.__maxTask = 500

    def __getDomainList(self):
        logger.info("resolve adblock dns backup...")
        domainList = []
        try:
            if os.path.exists(self.__domainlistFile):
                with open(self.__domainlistFile, 'r') as f:
                    tmp = f.readlines()
                    domainList = list(map(lambda x: x.replace("\n", ""), tmp))
        except Exception as e:
            logger.error("%s"%(e))
        finally:
            logger.info("adblock dns backup: %d"%(len(domainList)))
            return domainList
        
    def __getDomainSet_CN(self):
        logger.info("resolve China domain list...")
        fullSet,domainSet,regexpSet,keywordSet = set(),set(),set(),set()
        try:
            domain_cn = ChinaDomian(self.__domainlistFile_CN, self.__domainlistUrl_CN)
            domain_apple = ChinaDomian(self.__domainlistFile_CN_Apple, self.__domainlistUrl_CN_Apple)
            domain_google = ChinaDomian(self.__domainlistFile_CN_Google, self.__domainlistUrl_CN_Google)

            fullSet = domain_cn.fullSet | domain_apple.fullSet | domain_google.fullSet
            domainSet = domain_cn.domainSet | domain_apple.domainSet | domain_google.domainSet
            regexpSet = domain_cn.regexpSet | domain_apple.regexpSet | domain_google.regexpSet
            keywordSet = domain_cn.keywordSet | domain_apple.keywordSet | domain_google.keywordSet
        except Exception as e:
            logger.error("%s"%(e))
        finally:
            logger.info("China domain list: full[%d], domain[%d], regexp[%d], keyword[%d]"%(len(fullSet),len(domainSet),len(regexpSet),len(keywordSet)))
            return fullSet,domainSet,regexpSet,keywordSet
        
    def __getIPDict_CN(self):
        logger.info("resolve China IP list...")
        IPDict = dict()
        try:
            if os.path.exists(self.__iplistFile_CN):
                os.remove(self.__iplistFile_CN)
            
            with httpx.Client() as client:
                response = client.get(self.__iplistUrl_CN)
                response.raise_for_status()
                with open(self.__iplistFile_CN,'wb') as f:
                    f.write(response.content)
            
            if os.path.exists(self.__iplistFile_CN):
                with open(self.__iplistFile_CN, 'r') as f:
                    for line in f.readlines():
                        row = line.replace("\n", "").split("/")
                        ip, offset = row[0], int(row[1])
                        IPDict[IPy.parseAddress(ip)[0]] = offset
        except Exception as e:
            logger.error("%s"%(e))
        finally:
            logger.info("China IP list: %d"%(len(IPDict)))
            return IPDict
    
    async def __resolve(self, dnsresolver, domain):
        ipList = []
        try:
            query_object = await dnsresolver.resolve(qname=domain, rdtype="A")
            query_item = None
            for item in query_object.response.answer:
                if item.rdtype == DNSRdataType.A:
                    query_item = item
                    break
            if query_item is None:
                raise Exception("not A type")
            for item in query_item:
                ip = '{}'.format(item)
                if ip != "0.0.0.0":
                    ipList.append(ip)
        except Exception as e:
            logger.error('"%s": %s' % (domain, e if e else "Resolver failed"))
        finally:
            return ipList

    async def __pingx(self, dnsresolver, domain, semaphore):
        async with semaphore: # 限制并发数，超过系统限制后会报错Too many open files
            host = domain
            port = None
            ipList = []
            if domain.rfind(":") > 0: # 兼容 host:port格式
                offset = domain.rfind(":")
                host = domain[ : offset]
                port = int(domain[offset + 1 : ])
            try:
                get_tld(host, fix_protocol=True, as_object=True) # 确认是否为域名
            except Exception as e:
                port = 80
            if port:
                try:
                    _, writer = await asyncio.open_connection(host, port)
                    writer.close()
                    await writer.wait_closed()
                    ipList.append(host)
                except Exception as e:
                    if port == 80:
                        port = 443
                        try:
                            _, writer = await asyncio.open_connection(host, port)
                            writer.close()
                            await writer.wait_closed()
                            ipList.append(host)
                        except Exception as e:
                            logger.error('"%s": %s' % (domain, e if e else "Connect failed"))
            else:
                count = 3
                while len(ipList) < 1 and count > 0:
                    ipList = await self.__resolve(dnsresolver, host)
                    count -= 1

            logger.info("%s: %s" % (domain, ipList))
            return domain, ipList

    def __generateBlackList(self, blackList):
        logger.info("generate black list...")
        try:
            if os.path.exists(self.__blacklistFile):
                os.remove(self.__blacklistFile)
            
            with open(self.__blacklistFile, "w") as f:
                for domain in blackList:
                    f.write("%s\n"%(domain))
            logger.info("block domain: %d"%(len(blackList)))
        except Exception as e:
            logger.error("%s"%(e))
    
    def __generateChinaList(self, ChinaList):
        logger.info("generate China list...")
        try:
            if os.path.exists(self.__ChinalistFile):
                os.remove(self.__ChinalistFile)
            
            with open(self.__ChinalistFile, "w") as f:
                for domain in ChinaList:
                    f.write("%s\n"%(domain))
            logger.info("China domain: %d"%(len(ChinaList)))
        except Exception as e:
            logger.error("%s"%(e))

    def __testDomain(self, domainList, nameservers, port=53):
        logger.info("resolve domain...")
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
            task = asyncio.ensure_future(self.__pingx(dnsresolver, domain, semaphore))
            taskList.append(task)
        # 等待异步任务结束
        loop.run_until_complete(asyncio.wait(taskList))
        # 获取异步任务结果
        domainDict = {}
        for task in taskList:
            domain, ipList = task.result()
            domainDict[domain] = ipList

        logger.info("resolve domain: %d"%(len(domainDict)))
        return domainDict

    def __isChinaDomain(self, domain, ipList, fullSet_CN, domainSet_CN, regexpSet_CN, keywordSet_CN, IPDict_CN):
        isChinaDomain = False
        try:
            if domain.find(':') > 0:
                domain = domain[ : domain.find(':')]
            
            while True:
                try:
                    res = get_tld(domain, fix_protocol=True, as_object=True)
                    if domain[-3:] == ".cn":
                        isChinaDomain = True
                        break
                    # full:
                    if domain in fullSet_CN:
                        isChinaDomain = True
                        break
                    # doamin:
                    if res.fld in domainSet_CN:
                        isChinaDomain = True
                        break
                    # regexp:
                    for regexp in regexpSet_CN:
                        if re.match(regexp, domain):
                            isChinaDomain = True
                            break
                    if isChinaDomain:
                        break
                    # keyword:
                    for keyword in keywordSet_CN:
                        if re.match(".*%s.*"%(keyword), domain):
                            isChinaDomain = True
                            break
                    if isChinaDomain:
                        break
                    # IP
                    raise Exception("try to resolve ip")
                except Exception as e:
                    # IP
                    for ip in ipList:
                        ip = IPy.parseAddress(ip)[0]
                        for k, v in IPDict_CN.items():
                            if (ip ^ k) >> (32 - v)  == 0:
                                isChinaDomain = True
                                break
                        if isChinaDomain:
                            break
                break
        except Exception as e: 
            logger.error('"%s": not domain'%(domain))
        finally:
            return domain,isChinaDomain

    def generate(self):
        try:
            domainList = self.__getDomainList()
            if len(domainList) < 1:
                return
            #domainList = domainList[:1000] # for test
            
            domainDict = self.__testDomain(domainList, ["127.0.0.1"], 5053) # 使用本地 smartdns 进行域名解析，配置3组国内、3组国际域名解析服务器，提高识别效率
            #domainDict = self.__testDomain(domainList, ["1.12.12.12"], 53) # for test

            fullSet_CN,domainSet_CN,regexpSet_CN,keywordSet_CN = self.__getDomainSet_CN()
            IPDict_CN = self.__getIPDict_CN()
            blackList = []
            if len(domainSet_CN) > 100 and len(IPDict_CN) > 100:
                thread_pool = ThreadPoolExecutor(max_workers=os.cpu_count() if os.cpu_count() > 4 else 4)
                taskList = []
                for domain in domainList:
                    if len(domainDict[domain]):
                        taskList.append(thread_pool.submit(self.__isChinaDomain, domain, domainDict[domain], fullSet_CN, domainSet_CN, regexpSet_CN, keywordSet_CN, IPDict_CN))
                    else:
                        blackList.append(domain)
                # 获取解析结果
                ChinaSet_tmp = set()
                for future in as_completed(taskList):
                    domain,isChinaDomain = future.result()
                    if isChinaDomain:
                        ChinaSet_tmp.add(domain)
                # 生成China域名列表
                ChinaList = []
                for domain in domainList:
                    if domain in ChinaSet_tmp:
                        ChinaList.append(domain)
                if len(ChinaList):
                    self.__generateChinaList(ChinaList)
            else:
                for domain in domainList:
                    if domainDict[domain] is None:
                        blackList.append(domain)

            # 生成黑名单
            if len(blackList):
                self.__generateBlackList(blackList)
        except Exception as e:
            logger.error("%s"%(e))

if __name__ == "__main__":
    '''
    # for test
    logFile = os.getcwd() + "/adblock.log"
    if os.path.exists(logFile):
        os.remove(logFile)
    logger.add(logFile)
    '''
    blackList = BlackList()
    blackList.generate()