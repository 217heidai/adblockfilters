import os
import time
import asyncio
import re
import sqlite3
from concurrent.futures import ThreadPoolExecutor,as_completed
from typing import Dict,List,Tuple,Set

import httpx
import IPy
from tld import get_tld
from loguru import logger
from dns.asyncresolver import Resolver as DNSResolver
from dns.rdatatype import RdataType as DNSRdataType

class DomainDatabase(object):
    def __init__(self, dbFile: str):
        self.__table_domain = "T_DOMAIN"
        self.__conn = sqlite3.connect(dbFile)
        self.__execute('PRAGMA synchronous = OFF')
        self.__init_db()

    def close(self):
        self.__conn.close()

    def __execute(self, sql:str):
        try:
            return self.__conn.execute(sql)
        except (sqlite3.OperationalError, sqlite3.IntegrityError) as e:
            logger.exception(e)

    def __checkTableExists(self, tableName:str) -> bool: # 检查TABLE是否存在
        try:
            sql = "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            tableList = []
            for row in self.__execute(sql):
                tableList.append(row[0])
            if tableName in tableList:
                return True
            return False
        except (sqlite3.OperationalError, sqlite3.IntegrityError) as e:
            logger.exception(e)
            return False

    def __updateData(self, sql:str, dataListTuple:list=None): # 批量更新
        try:
            c = self.__conn.cursor() #获取游标
            if dataListTuple:
                c.executemany(sql, dataListTuple)
            else:
                c.execute(sql)
            self.__conn.commit()
        except  (sqlite3.OperationalError, sqlite3.IntegrityError) as e:
            logger.exception(e)
        finally:
            c.close()

    def __init_db(self):
        isExists = self.__checkTableExists(self.__table_domain)
        if not isExists:
            self.__execute('CREATE TABLE %s (  ID INTEGER PRIMARY KEY AUTOINCREMENT,\
                                                    domain TEXT NOT NULL,\
                                                    fld TEXT,\
                                                    subdomain TEXT,\
                                                    ip TEXT,\
                                                    port INTEGER,\
                                                    isBlock INTEGER NOT NULL CHECK (isBlock IN (0, 1)) DEFAULT 0,\
                                                    isChina INTEGER NOT NULL CHECK (isChina IN (0, 1)) DEFAULT 0,\
                                                    timeStamp INTEGER NOT NULL,\
                                                    ipList TEXT)'%(self.__table_domain))
            self.__execute('CREATE UNIQUE INDEX INDEX_%s_UNIQUE on %s (domain)'%(self.__table_domain, self.__table_domain))
            self.__execute('CREATE INDEX index_%s on %s (isBlock, isChina, timeStamp, fld, domain, ip, port)'%(self.__table_domain, self.__table_domain))
    
    def getAll(self) -> List[Tuple]:
        sql = "SELECT domain,fld,subdomain,ip,port,isBlock,isChina,timeStamp,ipList FROM %s"%(self.__table_domain)
        return self.__execute(sql)

    def updateALL(self, domainList:List[Tuple]):
        sql = "REPLACE INTO %s (domain, fld, subdomain, ip, port, isBlock, isChina, timeStamp, ipList) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"%(self.__table_domain)
        self.__updateData(sql, domainList)

class DOMAIN(object):
    def __init__(self, domain:str, fld:str=None, subdomain:str=None, ip:str=None, port:int=None, isBlock:int=None, isChina:int=None, timeStamp:int=None, ipList:str=None):
        self.domain = domain
        if timeStamp:
            self.fld = fld
            self.subdomain = subdomain
            self.ip = ip
            self.port = port
            self.__isBlock = isBlock
            self.__isChina = isChina
            self.__timeStamp = timeStamp
            self.__ipList = ipList.split(',') if ipList else []
            self.__update = False
        else:
            self.fld, self.subdomain, self.ip, self.port = self.__ip_or_domain(self.domain)
            self.__isBlock = 0
            self.__isChina = 0
            self.__timeStamp = int(time.time())
            self.__ipList = []
            self.__update = True
        
    def __ip_or_domain(self, address:str) -> Tuple[str]: # ip, fld, subdomain
        fld, subdomain, ip, port = None, None, None, None
        try:
            res = get_tld(address, fix_protocol=True, as_object=True)
            fld = res.fld
            subdomain = res.subdomain if len(res.subdomain) else None
            return fld, subdomain, ip, port
        except Exception as e:
            try:
                if address.find(":") > 0:
                    ip_address = IPy.IP(address[:address.find(":")])
                    if ip_address.iptype() == "PUBLIC":
                        ip = address[ : address.find(":")]
                        port = address[address.find(":")+1 : ]
                else:
                    ip_address = IPy.IP(address)
                    if ip_address.iptype() == "PUBLIC":
                        ip = address
            except Exception as e:
                logger.error('"%s": not domain or ip'%(address))
            return fld, subdomain, ip, port
    
    def getTimeStamp(self) -> int:
        return self.__timeStamp

    def setBlock(self, isBlock:bool):
        f = 1 if isBlock else 0
        if self.__isBlock != f:
            self.__isBlock = f
            self.__update = True
    
    def getBlock(self) -> bool:
        return True if self.__isBlock else False
    
    def setChina(self, isChina:bool):
        f = 1 if isChina else 0
        if self.__isChina != f:
            self.__isChina = f
            self.__update = True
    
    def getChina(self) -> bool:
        return True if self.__isChina else False

    def setIPList(self, ipList:List[str]):
        if set(self.__ipList) != set(ipList):
            self.__ipList = ipList
            self.__update = True
    
    def getIPList(self) -> List[str]:
        return self.__ipList

    def getUpdate(self) -> bool:
        return self.__update

    def toTuple(self) -> Tuple:
        L = list()
        L.append(self.domain)
        L.append(self.fld)
        L.append(self.subdomain)
        L.append(self.ip)
        L.append(self.port)
        L.append(self.__isBlock)
        L.append(self.__isChina)
        L.append(self.__timeStamp)
        L.append(','.join(map(str, self.__ipList)) if len(self.__ipList) else None)
        return tuple(L)


class BlackList(object):
    def __init__(self, path:str):
        self.__databaseFile = os.path.join(path, "domain.db")
        self.__ChinalistFile = os.path.join(path, "rules/china.txt")
        self.__blacklistFile = os.path.join(path, "rules/black.txt")
        self.__domainlistFile = os.path.join(path, "rules/domain.txt")
        self.__directlistFile = os.path.join(path, "rules/direct.txt")
        self.__directlistUrl = "https://raw.githubusercontent.com/217heidai/RoutingRules/main/rules/direct.txt"
        self.__IPlistFile = os.path.join(path, "rules/ipv4_china.txt")
        self.__IPlistUrl = "https://raw.githubusercontent.com/217heidai/RoutingRules/main/rules/ipv4_china.txt"
        self.__maxTask = 500

        self.__db = DomainDatabase(self.__databaseFile)
    
    def close(self):
        self.__db.close()

    def __download(self, fileName, url):
        try:
            '''
            ################################
            # for test
            if os.path.exists(fileName):
                return
            ################################
            '''

            fileNameDownload = fileName + ".download"
            if os.path.exists(fileNameDownload):
                os.remove(fileNameDownload)
            
            with httpx.Client() as client:
                logger.info(f'download %s[%s]' % (os.path.basename(fileName), url))
                response = client.get(url)
                response.raise_for_status()
                contentType = response.headers.get("Content-Type")
                if contentType.find("text/plain") < 0:
                    raise Exception("Content-Type[%s] error"%(contentType))
                with open(fileNameDownload,'wb') as f:
                    f.write(response.content)
            
            if os.path.exists(fileName):
                os.remove(fileName)

            os.rename(fileNameDownload, fileName)

            return True
        except Exception as e:
            logger.error(f'%s download failed: %s' % (fileName, e))
            return False

    def __getDomainDict(self, domainDict:Dict[str, DOMAIN]) -> Dict[str, DOMAIN]:
        logger.info("resolve domain list...")
        try:
            if os.path.exists(self.__domainlistFile):
                with open(self.__domainlistFile, 'r') as f:
                    for line in f.readlines():
                        # 去掉换行符
                        line = line.replace('\r', '').replace('\n', '').strip()
                        # 去掉空行
                        if len(line) < 1:
                            continue
                        # 去掉注释
                        if line.startswith('#'):
                            continue
                        
                        if line not in domainDict:
                            domainDict[line] = DOMAIN(line)

            logger.info("domain dict: %d"%(len(domainDict)))
            return domainDict
        except Exception as e:
            logger.error("%s"%(e))
            return domainDict
        
    def __getDomainSet_CN(self) -> Tuple[Set]:
        logger.info("resolve China domain list...")
        fullSet,domainSet,regexpSet,keywordSet = set(),set(),set(),set()
        try:
            self.__download(self.__directlistFile, self.__directlistUrl)
            if os.path.exists(self.__directlistFile):
                with open(self.__directlistFile, 'r') as f:
                    for line in f.readlines():
                        # 去掉换行符
                        line = line.replace('\r', '').replace('\n', '').strip()
                        # 去掉空行
                        if len(line) < 1:
                            continue
                        # 去掉注释
                        if line.startswith('#'):
                            continue
                        # regexp
                        if line.startswith('regexp:'):
                            regexpSet.add(line[len('regexp:'):])
                            continue
                        # keyword
                        if line.startswith('keyword:'):
                            keywordSet.add(line[len('keyword:'):])
                            continue
                        if line.startswith('full:'):
                            fullSet.add(line[len('full:'):])
                            continue
                        if line.startswith('domain:'):
                            domainSet.add(line[len('domain:'):])
                            continue
            
            logger.info("China domain list: full[%d], domain[%d], regexp[%d], keyword[%d]"%(len(fullSet),len(domainSet),len(regexpSet),len(keywordSet)))
            return fullSet,domainSet,regexpSet,keywordSet
        except Exception as e:
            logger.error("%s"%(e))
            return fullSet,domainSet,regexpSet,keywordSet
        
    def __getIPDict_CN(self) -> Dict[int, int]:
        logger.info("resolve China IP list...")
        IPDict = dict()
        try:
            self.__download(self.__IPlistFile, self.__IPlistUrl)            
            if os.path.exists(self.__IPlistFile):
                with open(self.__IPlistFile, 'r') as f:
                    for line in f.readlines():
                        row = line.replace('\r', '').replace("\n", "").split("/")
                        ip, offset = row[0], int(row[1])
                        IPDict[IPy.parseAddress(ip)[0]] = offset
            
            logger.info("China IP list: %d"%(len(IPDict)))
            return IPDict
        except Exception as e:
            logger.error("%s"%(e))
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
            return ipList
        except Exception as e:
            logger.error('"%s": %s' % (domain, e if e else "Resolver failed"))
            return ipList

    async def __pingx(self, dnsresolver:DNSResolver, domain:DOMAIN, semaphore):
        async def connect_with_timeout(ip, port, timeout=5):
            writer = None
            try:
                # 用 wait_for 包裹 open_connection，设定总超时
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=timeout
                )
                return True                
            except asyncio.TimeoutError:
                logger.error('"%s": connect time out' % (ip))
                return False
            except ConnectionRefusedError:
                logger.error('"%s": connect refused' % (ip))
                return False
            except Exception as e:
                logger.error('"%s": %s' % (ip, e if e else "Connect failed"))
                return False
            finally:
                # 确保资源释放
                if writer:
                    writer.close()
                    await writer.wait_closed()

        async with semaphore: # 限制并发数，超过系统限制后会报错Too many open files
            ipList = []
            if domain.ip:  # IP
                portList = [domain.port] * 3 if domain.port else [80, 443] * 3 # 重试 3 次
                for port in portList:
                    if await connect_with_timeout(domain.ip, port, 5): # 5s 超时
                        ipList.append(domain.ip)
                        break
            else: # 域名
                count = 3
                while len(ipList) < 1 and count > 0:
                    ipList = await self.__resolve(dnsresolver, domain.domain)
                    count -= 1

            domain.setIPList(ipList)
            logger.info("%s: %s" % (domain.domain, ipList))
            return domain

    def __generateBlackList(self, blackList):
        logger.info("generate black list...")
        try:
            if os.path.exists(self.__blacklistFile):
                os.remove(self.__blacklistFile)
            
            with open(self.__blacklistFile, "w") as f:
                for domain in blackList:
                    f.write("%s\n"%(domain))
            logger.info("black domain: %d"%(len(blackList)))
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

    def __testDomain(self, domainDict:Dict[str,DOMAIN], nameservers:str, port=53):
        logger.info("resolve domain...")

        async def _resolve_all():
            dnsresolver = DNSResolver()
            dnsresolver.nameservers = nameservers
            dnsresolver.port = port
            semaphore = asyncio.Semaphore(self.__maxTask)

            tasks = []
            now = int(time.time()) 
            for _,v in domainDict.items():
                ipList = v.getIPList()
                if len(ipList) < 1: # ipList 为空，重新解析
                    tasks.append(self.__pingx(dnsresolver, v, semaphore))
                else:
                    if now - v.getTimeStamp() > 3110400: # 超过 36 天，重新解析
                        tasks.append(self.__pingx(dnsresolver, v, semaphore))
            results = await asyncio.gather(*tasks)

            for domain in results:
                domainDict[domain.domain] = domain

            logger.info("resolve domain: %d" % len(domainDict))
            return domainDict

        return asyncio.run(_resolve_all())

    def __isChinaDomain(self, domain:DOMAIN, fullSet_CN:Set[str], domainSet_CN:Set[str], regexpSet_CN:Set[str], keywordSet_CN:Set[str], IPDict_CN:Set[str]):
        try:
            # 从域名识别
            if domain.fld:
                # .cn 域名默认为国内
                if domain.fld[-3:] == ".cn":
                    domain.setChina(True)
                    return domain
                # full:
                if domain.domain in fullSet_CN:
                    domain.setChina(True)
                    return domain
                # doamin:
                if domain.fld in domainSet_CN:
                    domain.setChina(True)
                    return domain
                # regexp:
                for regexp in regexpSet_CN:
                    if re.match(regexp, domain.domain):
                        domain.setChina(True)
                        return domain
                # keyword:
                for keyword in keywordSet_CN:
                    if re.match(r".*%s.*"%(keyword), domain.domain):
                        domain.setChina(True)
                        return domain

            # 从 IP 识别
            ipList = domain.getIPList()
            for ip in ipList:
                ip = IPy.parseAddress(ip)[0]
                for k, v in IPDict_CN.items():
                    if (ip ^ k) >> (32 - v)  == 0:
                        domain.setChina(True)
                        return domain
            
            domain.setChina(False)
            return domain
        except Exception as e: 
            logger.error('"%s": not domain'%(domain))
            domain.setChina(False)
            return domain

    def __getDomainDict_db(self) -> Dict[str, DOMAIN]:
        logger.info("get domain list from db...")
        domainDict = dict()
        try:
            for line in self.__db.getAll():
                domainDict[line[0]] = DOMAIN(line[0], line[1], line[2], line[3], line[4], line[5], line[6], line[7], line[8])

            logger.info("domain dict: %d"%(len(domainDict)))
            return domainDict
        except Exception as e:
            logger.error("%s"%(e))
            return domainDict
    
    def __updateDomainDict_db(self, domainDict:Dict[str, DOMAIN]):
        logger.info("update domain list to db...")
        try:
            L = list()
            for _,v in domainDict.items():
                if v.getUpdate():
                    L.append(v.toTuple())
            
            if len(L):
                self.__db.updateALL(L)
        except Exception as e:
            logger.error("%s"%(e))

    def generate(self):
        try:
            # 获取数据库域名清单
            domainDict = self.__getDomainDict_db()

            # 获取域名清单 https://raw.githubusercontent.com/217heidai/adblockfilters/refs/heads/main/rules/domain.txt
            domainDict = self.__getDomainDict(domainDict)
            if len(domainDict) < 1:
                return
            
            # 获取直连域名清单 https://raw.githubusercontent.com/217heidai/RoutingRules/main/rules/direct.txt
            fullSet_CN,domainSet_CN,regexpSet_CN,keywordSet_CN = self.__getDomainSet_CN()

            # 获取国内 IP 清单 https://raw.githubusercontent.com/217heidai/RoutingRules/main/rules/ipv4_china.txt
            IPDict_CN = self.__getIPDict_CN()
            
            # 域名解析
            '''
            #################################################################
            # for test
            import itertools
            first_1000 = dict(itertools.islice(domainDict.items(), 1000))
            domainDict = self.__testDomain(first_1000, ["192.168.3.1"], 5053)
            #################################################################
            '''
            domainDict = self.__testDomain(domainDict, ["127.0.0.1"], 5053) # 使用本地 smartdns 进行域名解析，配置3组国内、3组国际域名解析服务器，提高识别效率

            # 国内域名识别
            thread_pool = ThreadPoolExecutor(max_workers=os.cpu_count() if os.cpu_count() > 4 else 4)
            taskList = []
            for _,v in domainDict.items():
                ipList = v.getIPList()
                if len(ipList):
                    taskList.append(thread_pool.submit(self.__isChinaDomain, v, fullSet_CN, domainSet_CN, regexpSet_CN, keywordSet_CN, IPDict_CN))
            for future in as_completed(taskList):
                domain:DOMAIN = future.result()
                if domain.getChina():
                    domainDict[domain.domain] = domain
            
            # 生成 Black 域名列表
            blackList = []
            for k,v in domainDict.items():
                ipList = v.getIPList()
                if len(ipList) == 0:
                    v.setBlock(True)
                    blackList.append(k)
                else:
                    v.setBlock(False)
            if len(blackList):
                blackList.sort()
                self.__generateBlackList(blackList)

            # 生成 China 域名列表
            ChinaList = []
            for k,v in domainDict.items():
                if v.getChina() and not v.getBlock():
                    ChinaList.append(k)
            if len(ChinaList):
                ChinaList.sort()
                self.__generateChinaList(ChinaList)
            
            # 更新数据库域名清单
            self.__updateDomainDict_db(domainDict)
            
        except Exception as e:
            logger.error("%s"%(e))

if __name__ == "__main__":
    path = os.getcwd()
    '''
    ############################################
    # for test
    logFile = os.path.join(path, "adblock.log")
    if os.path.exists(logFile):
        os.remove(logFile)
    logger.add(logFile)
    ############################################
    '''

    blackList = BlackList(path)
    blackList.generate()
    blackList.close()