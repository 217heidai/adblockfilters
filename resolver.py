import os
import sys
import re

from tld import get_tld
import IPy

class Resolver(object):
    def __init__(self, fileName):
        self.__fileName = fileName

    def __Analysis(self, address):
        try:
            res = get_tld(address, fix_protocol=True, as_object=True)
            return res.fld, res.subdomain
        except Exception as e: 
            ip = address
            if ip.rfind(":") > 0:
                ip = ip[:ip.rfind(":")]
            try:
                ip_address = IPy.IP(ip)
            except Exception as e: 
                raise Exception ("not domain or ip: %s"%(address))
            if ip_address.iptype() != "PUBLIC":
                raise Exception ("not public ip: %s"%(address))
            return address, ""

    # host 模式
    def __ResolveHost(self, line):
        def match(pattern, string):
            return True if re.match(pattern, string) else False
        try:
            block,unblock,filter=None,None,None
            while True:
                # #* 注释
                if match('^#.*', line):
                    break
                if line.find('0.0.0.0')==0 or line.find('127.0.0.1') == 0:
                    row = line.split(' ')
                    row = list(map(lambda x: x.strip(), row)) # 字段去空格
                    for i in range(len(row)-1):
                        if len(row[i]) == 0:
                            row.pop(i)
                    domain = row[1]
                    if domain not in ['localhost', 'localhost.localdomain', 'local', '0.0.0.0']:
                        block = self.__Analysis(domain)
                        break
                    print("无法识别的规则：%s"%(line))
                    break
                print("无法识别的规则：%s"%(line))
                break
        except Exception as e:
            print("%s.%s: %s" % (self.__class__.__name__, sys._getframe().f_code.co_name, e))
        finally:
            return block,unblock,filter
        
    # dns 模式
    def __ResolveDNS(self, line):
        def match(pattern, string):
            return True if re.match(pattern, string) else False
        try:
            block,unblock,filter=None,None,None
            while True:
                # !* 注释
                if match('^!.*', line):
                    break
                # [*] 注释
                if match('^\[.*\]$', line):
                    break
                # #* 注释
                if match('^#.*', line):
                    break

                # ||example.org^: block access to the example.org domain and all its subdomains, like www.example.org.
                if match('^\|\|.*\^$', line):
                    domain = line[2:-1]
                    if domain.find('*') >= 0 or domain.find('/') >= 0:
                        filter = line
                        break
                    block = self.__Analysis(domain)
                    break
                # @@||example.org^: unblock access to the example.org domain and all its subdomains.
                if match('^@@\|\|.*\^$', line):
                    domain = line[4:-1]
                    if domain.find('*') >= 0 or domain.find('/') >= 0:
                        filter = line
                        break
                    unblock = self.__Analysis(domain)
                    break
                # /REGEX/: block access to the domains matching the specified regular expression
                if match('^/.*/$', line):
                    filter = line
                    break
                # other
                print("无法识别的规则：%s"%(line))
                break
        except Exception as e:
            print("%s.%s: %s" % (self.__class__.__name__, sys._getframe().f_code.co_name, e))
        finally:
            return block,unblock,filter
        
    # filter 模式
    def __ResolveFilter(self, line):
        def match(pattern, string):
            return True if re.match(pattern, string) else False
        try:
            block,unblock,filter=None,None,None
            while True:
                # !* 注释
                if match('^!.*', line):
                    break
                # [*] 注释
                if match('^\[.*\]$', line):
                    break
                # #* 注释
                if match('^#.*', line):
                    break

                # ||example.org^: block access to the example.org domain and all its subdomains, like www.example.org.
                if match('^\|\|.*\^$', line):
                    domain = line[2:-1]
                    if domain.find('*') >= 0 or domain.find('/') >= 0:
                        filter = line
                        break
                    block = self.__Analysis(domain)
                    break
                # @@||example.org^: unblock access to the example.org domain and all its subdomains.
                if match('^@@\|\|.*\^$', line):
                    domain = line[4:-1]
                    if domain.find('*') >= 0 or domain.find('/') >= 0:
                        filter = line
                        break
                    unblock = self.__Analysis(domain)
                    break
                # /REGEX/: block access to the domains matching the specified regular expression
                if match('^/.*/$', line):
                    filter = line
                    break
                # other
                filter = line
                break
        except Exception as e:
            print("%s.%s: %s" % (self.__class__.__name__, sys._getframe().f_code.co_name, e))
        finally:
            return block,unblock,filter

    def Resolve(self, type):
        blockDict = dict()
        unblockDict = dict()
        filterList = []

        if not os.path.exists(self.__fileName):
            return blockDict,unblockDict,filterList
        
        print("解析：%s..."%(os.path.basename(self.__fileName))) # 处理信息输出
        with open(self.__fileName, "r") as f:
            for line in f:
                # 去掉换行符
                line = line.replace('\r', '').replace('\n', '').strip()
                # 去掉空行
                if len(line) < 1:
                    continue

                block,unblock,filter=None,None,None
                if type == "host":
                    block,unblock,filter = self.__ResolveHost(line)

                if type == "dns":
                    block,unblock,filter = self.__ResolveDNS(line)

                if type == "filter":
                    block,unblock,filter = self.__ResolveFilter(line)
                
                if block:
                    if block[0] not in blockDict:
                        blockDict[block[0]] = [block[1]]
                    else:
                        blockDict[block[0]].append(block[1])
                if unblock:
                    if unblock[0] not in unblockDict:
                        unblockDict[unblock[0]] = [unblock[1]]
                    else:
                        unblockDict[unblock[0]].append(unblock[1])
                if filter:
                    filterList.append(filter)
        return blockDict,unblockDict,filterList

if __name__ == '__main__':
    pwd = os.getcwd()
    file = pwd + '/rules/ADgk.txt' 
    resolver = Resolver(file)
    #blockList, unblockList, filterList = resolver.Resolve("host") #1024_hosts、ad-wars_hosts、StevenBlack_hosts
    blockList, unblockList, filterList = resolver.Resolve("dns") #1Hosts_(Lite)、AdRules_DNS_List、Hblock、NEO_DEV_HOST、Notracking_blocklist、OISD_Basic
    #blockList, unblockList, filterList = resolver.Resolve("filter") #ADgk、AdGuard_Base_filter、AdGuard_Chinese_filter、AdGuard_DNS_filter
    print('blockList: %s'%(len(blockList)))
    print('unblockList: %s'%(len(unblockList)))
    print('filterList: %s'%(len(filterList)))