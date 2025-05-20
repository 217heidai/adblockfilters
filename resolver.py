import os
import sys
import re
from typing import Tuple,Dict,Set,List

from tld import get_tld
import IPy
from loguru import logger

from readme import Rule

class Resolver(object):
    def __init__(self, path:str):
        self.path = path
        self.options = {# Adblock Plus filter options
                        'script',         '~script',
                        'image',          '~image',
                        'stylesheet',     '~stylesheet',
                        'object',         '~object',
                        'subdocument',    '~subdocument',
                        'xmlhttprequest', '~xmlhttprequest',
                        'websocket',      '~websocket',
                        'webrtc',         '~webrtc',
                        'popup',
                        'generichide',
                        'genericblock',
                        'document',
                        'elemhide',
                        'third-party', '~third-party',
                        'ping',
                        'other',
                        'match-case',
                        # AdGuard Advanced capabilities
                        'ctag',
                        'all',
                        'redirect',
                        'stealth',
                        'domain'
                    }
    
    def __ip_or_domain(self, address:str) -> Tuple[str]: # ip, fld, subdomain
        ip, fld, subdomain = None, None, None
        try:
            res = get_tld(address, fix_protocol=True, as_object=True)
            fld = res.fld
            subdomain = res.subdomain
        except Exception as e:
            try:
                ip_address = IPy.IP(address)
                if ip_address.iptype() == "PUBLIC":
                    ip = address
            except Exception as e:
                pass
        finally:
            return ip, fld, subdomain
    
    def __analysis(self, address:str) -> Tuple[str]:
        address_tmp = address
        if address.rfind(":") > 0:
            address_tmp = address[ : address.rfind(":")]
        ip, fld, subdomain = self.__ip_or_domain(address_tmp)
        if ip:
            return address, "" # 可能包含port，因此直接return address
        if fld:
            return fld, subdomain
        raise Exception('"%s": not domain or public ip'%(address))

    # host 模式
    def __resolveHost(self, line) -> Tuple[str]:
        def match(pattern, string):
            return True if re.match(pattern, string) else False
        try:
            block=None
            while True:
                # #* 注释
                if match('^#.*', line):
                    break

                line = line.replace('\t', ' ')
                
                if line.find('#') > 0:
                    line = line[:line.find('#')].strip()
                
                if line.startswith('0.0.0.0') or line.startswith('127.0.0.1'):
                    row = line.split(' ')
                    domain = row[-1]
                    if domain not in {'localhost', 'localhost.localdomain', 'local', '0.0.0.0'}:
                        block = self.__analysis(domain)
                        break
                raise Exception('"%s": not keep'%(line))
        except Exception as e:
            logger.error("%s"%(e))
        finally:
            return block

    # 从 filter 规则中找出包含的域名
    def __resolveFilterDomain(self, filter) -> Tuple[str, str]:
        def match(pattern, string) -> bool:
            return True if re.match(pattern, string) else False
        domain = None
        try:
            domain_tmp = None
            while True:
                '''
                # for test
                if filter == "@@|https://media.amazon.map.fastly.net^$script":
                    print(filter)
                '''
                if filter.startswith('#%#var'):
                    break

                if filter.startswith('###'):
                    break

                if filter.startswith('##') and filter.find('://') < 0:
                    break

                if match('^/.*/$', filter):
                    break

                if match('^\|\|.*\*.*\^$', filter):
                    break

                # ||example.org^$option
                # @@||example.org^$option
                if match('^\|\|.*\^\$.*', filter) or match('^@@\|\|.*\^\$.*', filter):
                    for opt in self.options:
                        if match('^\|\|.*\^\$%s'%(opt), filter):
                            domain_tmp = filter[len('||'):filter.find('^$%s'%(opt))]
                            break
                        if match('^@@\|\|.*\^\$%s'%(opt), filter):
                            domain_tmp = filter[len('@@||'):filter.find('^$%s'%(opt))]
                            break
                    break
                # ||example.org
                if match('^\|\|.*', filter):
                    domain_tmp = filter[len('||'):]
                    if domain_tmp.find('/') > 0:
                        domain_tmp = domain_tmp[:domain_tmp.find('/')]
                    if domain_tmp.find('$') > 0:
                        domain_tmp = domain_tmp[:domain_tmp.find('$')]
                    if domain_tmp.find('^*') > 0:
                        domain_tmp = domain_tmp[:domain_tmp.find('^*')]
                    if domain_tmp.find('*') > 0:
                        domain_tmp = domain_tmp[:domain_tmp.find('*')]
                    break
                # @@||example.org
                if match('^@@\|\|.*', filter):
                    domain_tmp = filter[len('@@||'):]
                    if domain_tmp.find('/') > 0:
                        domain_tmp = domain_tmp[:domain_tmp.find('/')]
                    if domain_tmp.find('$') > 0:
                        domain_tmp = domain_tmp[:domain_tmp.find('$')]
                    if domain_tmp.find('^*') > 0:
                        domain_tmp = domain_tmp[:domain_tmp.find('^*')]
                    if domain_tmp.find('*') > 0:
                        domain_tmp = domain_tmp[:domain_tmp.find('*')]
                    break

                # ip$network
                if match('.*\$network$', filter):
                    domain_tmp = filter[:-len('$network')]
                    if domain_tmp.startswith('@@'):
                        domain_tmp = domain_tmp[2:]
                    break

                # example.org^
                if match('.*\^$', filter):
                    domain_tmp = filter[:-1]
                    break
                
                # ##
                # example.com##selector
                # ~example.com##selector
                # example.com,example.edu##selector
                # example.com,~mail.example.com##selector
                connector = '##'
                if match('.*%s.*'%(connector), filter) and not filter.startswith(connector) and not filter.endswith(connector):
                    domain_tmp = filter[ : filter.find(connector)]
                    if domain_tmp.find(',') > 0:
                        domain_tmp = None
                    break
                # #?#
                # example.com#?#selector
                # ~example.com#?#selector
                # example.com,example.edu#?#selector
                # example.com,~mail.example.com#?#selector
                connector = '#\?#'
                if match('.*%s.*'%(connector), filter) and not filter.startswith(connector) and not filter.endswith(connector):
                    domain_tmp = filter[ : filter.find('#?#')] # 需去掉转义符'#\?#' -> '#?#'
                    if domain_tmp.find(',') > 0:
                        domain_tmp = None
                    break
                # #@#
                # example.com#@#selector
                # ~example.com#@#selector
                # example.com,example.edu#@#selector
                # example.com,~mail.example.com#@#selector
                connector = '#@#'
                if match('.*%s.*'%(connector), filter) and not filter.startswith(connector) and not filter.endswith(connector):
                    domain_tmp = filter[ : filter.find(connector)]
                    if domain_tmp.find(',') > 0:
                        domain_tmp = None
                    break
                # #$#
                # example.com#$#selector
                # ~example.com#$#selector
                # example.com,example.edu#$#selector
                # example.com,~mail.example.com#$#selector
                connector = '#\$#'
                if match('.*%s.*'%(connector), filter) and not filter.startswith(connector) and not filter.endswith(connector):
                    domain_tmp = filter[ : filter.find('#$#')] # 需去掉转义符'#\$#' -> '#$#'
                    if domain_tmp.find(',') > 0:
                        domain_tmp = None
                    break
                # #%#
                # example.com#%#selector
                # ~example.com#%#selector
                # example.com,example.edu#%#selector
                # example.com,~mail.example.com#%#selector
                connector = '#%#'
                if match('.*%s.*'%(connector), filter) and not filter.startswith(connector) and not filter.endswith(connector):
                    domain_tmp = filter[ : filter.find(connector)]
                    if domain_tmp.find(',') > 0:
                        domain_tmp = None
                    break
                
                # a[href^="http://sarcasmadvisor.com/"]
                if match('.*http:\/\/.*', filter):
                    domain_tmp = filter[filter.find('http://') + len('http://'):]
                    if domain_tmp.startswith('*.'):
                        domain_tmp = domain_tmp[2:]
                    if domain_tmp.find("'") > 0:
                        domain_tmp = domain_tmp[:domain_tmp.find("'")]
                    if domain_tmp.find("^") > 0:
                        domain_tmp = domain_tmp[:domain_tmp.find("^")]
                    if domain_tmp.find('$') > 0:
                        domain_tmp = domain_tmp[:domain_tmp.find('$')]
                    if domain_tmp.find(',') > 0:
                        domain_tmp = None
                    break

                # a[href^="https://sarcasmadvisor.com/"]
                if match('.*https:\/\/.*', filter):
                    domain_tmp = filter[filter.find('https://') + len('https://'):]
                    if domain_tmp.startswith('*.'):
                        domain_tmp = domain_tmp[2:]
                    if domain_tmp.find("'") > 0:
                        domain_tmp = domain_tmp[:domain_tmp.find("'")]
                    if domain_tmp.find("^") > 0:
                        domain_tmp = domain_tmp[:domain_tmp.find("^")]
                    if domain_tmp.find('$') > 0:
                        domain_tmp = domain_tmp[:domain_tmp.find('$')]
                    if domain_tmp.find(',') > 0:
                        domain_tmp = None
                    break
                
                # 其它规则
                raise Exception('"%s": can not resolve domain or ip'%(filter))
            
            if domain_tmp:
                if domain_tmp.find('"') > 0:
                    domain_tmp = domain_tmp[:domain_tmp.find('"')]
                if domain_tmp.find('^') > 0:
                    domain_tmp = domain_tmp[:domain_tmp.find('^')]
                if domain_tmp.startswith('*.') > 0:
                    domain_tmp = domain_tmp[len('*.'):]
                if domain_tmp.startswith('~') or domain_tmp.startswith('/') or domain_tmp.startswith('.'):
                    domain_tmp = domain_tmp[1:]
                if domain_tmp.find('/') > 0:
                    domain_tmp = domain_tmp[:domain_tmp.find('/')]
                if len(domain_tmp) < 4 or domain_tmp.find('.') < 0 or domain_tmp.find('*') >= 0 or domain_tmp[-1]=='.' or domain_tmp.startswith('-'):
                    raise Exception('"%s": not include domain or ip'%(filter))
                try:
                    fld, subdomain = self.__analysis(domain_tmp)
                    if len(subdomain) > 0:
                        domain = "%s.%s"%(subdomain,fld)
                    else:
                        domain = "%s"%(fld)
                except Exception as e:
                    raise Exception('"%s": not include domain or ip'%(filter))
        except Exception as e:
            logger.error("%s"%(e))
        finally:
            return filter,domain

    # dns 模式
    def __resolveDNS(self, line) -> Tuple[Tuple[str],Tuple[str],Tuple[str]]:
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

                # 干掉注释
                if line.find('#') > 0:
                    line = line[:line.find('#')].strip()

                # ||example.org^
                if match('^\|\|.*\^$', line):
                    domain = line[2:-1]
                    if domain.find('*') >= 0:
                        if domain.startswith('*.') and domain[2:].find('*')<0:
                            domain = domain[2:]
                            block = self.__analysis(domain)
                            break
                        filter = line
                        break
                    block = self.__analysis(domain)
                    break
                # @@||example.org^
                if match('^@@\|\|.*\^$', line):
                    domain = line[4:-1]
                    if domain.find('*') >= 0:
                        if domain.startswith('*.') and domain[2:].find('*')<0:
                            domain = domain[2:]
                            unblock = self.__analysis(domain)
                            break
                        filter = line
                        break
                    unblock = self.__analysis(domain)
                    break
                # /REGEX/
                if match('^/.*/$', line):
                    filter = line
                    break
                # ||example. or ||example.org^$ctag=device_tv
                if match('^\|\|.*', line):
                    filter = line
                    break
                # other
                raise Exception('"%s": not keep'%(line))
            
            if filter:
                filter = self.__resolveFilterDomain(filter)
        except Exception as e:
            logger.error("%s"%(e))
        finally:
            return block,unblock,filter

    # filter 模式
    def __resolveFilter(self, line) -> Tuple[Tuple[str],Tuple[str],Tuple[str]]:
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
                # ## or ###
                if match('^##.*', line):
                    filter = line
                    break
                # #%#
                if match('^#%#.*', line):
                    filter = line
                    break
                # #* 注释
                if match('^#.*', line):
                    break

                # 干掉注释
                #if line.find(' #') > 0:
                #    line = line[:line.find(' #')].strip()

                # ||example.org^: block access to the example.org domain and all its subdomains, like www.example.org.
                if match('^\|\|.*\^$', line):
                    domain = line[2:-1]
                    if domain.find('/') >= 0:
                        filter = line
                        break
                    if domain.find('*') >= 0:
                        if domain.startswith('*.') and domain[2:].find('*')<0:
                            domain = domain[2:]
                            block = self.__analysis(domain)
                            break
                        else:
                            filter = line
                            break
                    block = self.__analysis(domain)
                    break
                # @@||example.org^: unblock access to the example.org domain and all its subdomains.
                if match('^@@\|\|.*\^$', line):
                    domain = line[4:-1]
                    if domain.find('*') >= 0 or domain.find('/') >= 0:
                        filter = line
                        break
                    unblock = self.__analysis(domain)
                    break
                # @@||example.org^|: unblock access to the example.org domain and all its subdomains.
                if match('^@@\|\|.*\^\|$', line):
                    domain = line[4:-2]
                    if domain.find('*') >= 0 or domain.find('/') >= 0:
                        filter = line
                        break
                    unblock = self.__analysis(domain)
                    break
                # /REGEX/: block access to the domains matching the specified regular expression
                if match('^/.*/$', line):
                    filter = line
                    break
                # 判断是否为单纯的域名
                if line.find('.')>0 and not line.startswith('*.') and not line.startswith('-') and line.find('=')<0 and line.find(':')<0 and line.find('*')<0 and line.find('_')<0 and line.find('?')<0 and line.find(';')<0 and line.find('|')<0 and line.find('$')<0 and line.find('#')<0 and line.find('/')<0 and line.find('%')<0 and line.find('^') < 0:
                    domain = line
                    block = self.__analysis(domain)
                    break
                # other
                filter = line
                break

            if filter:
                filter = self.__resolveFilterDomain(filter)
        except Exception as e:
            logger.error("%s"%(e))
        finally:
            return block,unblock,filter

    def resolveHost(self, rule:Rule) -> Tuple[Dict[str,Set[str]],Dict[str,Set[str]],Dict[str,str]]:
        blockDict:Dict[str,Set[str]] = dict()
        unblockDict:Dict[str,Set[str]] = dict()
        filterDict:Dict[str,str] = dict()

        filename = self.path + '/' + rule.filename

        if not os.path.exists(filename):
            return blockDict,unblockDict,filterDict

        with open(filename, "r") as f:
            for line in f:
                # 去掉换行符
                line = line.replace('\r', '').replace('\n', '').strip()
                # 去掉空行
                if len(line) < 1:
                    continue

                block = self.__resolveHost(line)
                
                if block:
                    if block[0] not in blockDict:
                        blockDict[block[0]] = {block[1],}
                    else:
                        blockDict[block[0]].add(block[1])
        logger.info("%s: block=%d, unblock=%d, filter=%d"%(rule.name,len(blockDict),len(unblockDict),len(filterDict)))
        return blockDict,unblockDict,filterDict

    def resolveDNS(self, rule:Rule) -> Tuple[Dict[str,Set[str]],Dict[str,Set[str]],Dict[str,str]]:
        blockDict:Dict[str,Set[str]] = dict()
        unblockDict:Dict[str,Set[str]] = dict()
        filterDict:Dict[str,str] = dict()

        filename = self.path + '/' + rule.filename

        if not os.path.exists(filename):
            return blockDict,unblockDict,filterDict

        with open(filename, "r") as f:
            for line in f:
                # 去掉换行符
                line = line.replace('\r', '').replace('\n', '').strip()
                # 去掉空行
                if len(line) < 1:
                    continue

                block,unblock,filter = self.__resolveDNS(line)
                
                if block:
                    if block[0] not in blockDict:
                        blockDict[block[0]] = {block[1],}
                    else:
                        blockDict[block[0]].add(block[1])
                if unblock:
                    if unblock[0] not in unblockDict:
                        unblockDict[unblock[0]] = {unblock[1],}
                    else:
                        unblockDict[unblock[0]].add(unblock[1])
                if filter:
                    filterDict[filter[0]] = filter[1]
        logger.info("%s: block=%d, unblock=%d, filter=%d"%(rule.name,len(blockDict),len(unblockDict),len(filterDict)))
        return blockDict,unblockDict,filterDict
    
    def resolveFilter(self, rule:Rule) -> Tuple[Dict[str,Set[str]],Dict[str,Set[str]],Dict[str,str]]:
        blockDict:Dict[str,Set[str]] = dict()
        unblockDict:Dict[str,Set[str]] = dict()
        filterDict:Dict[str,str] = dict()

        filename = self.path + '/' + rule.filename

        if not os.path.exists(filename):
            return blockDict,unblockDict,filterDict

        with open(filename, "r") as f:
            for line in f:
                # 去掉换行符
                line = line.replace('\r', '').replace('\n', '').strip()
                # 去掉空行
                if len(line) < 1:
                    continue

                block,unblock,filter = self.__resolveFilter(line)
                
                if block:
                    if block[0] not in blockDict:
                        blockDict[block[0]] = {block[1],}
                    else:
                        blockDict[block[0]].add(block[1])
                if unblock:
                    if unblock[0] not in unblockDict:
                        unblockDict[unblock[0]] = {unblock[1],}
                    else:
                        unblockDict[unblock[0]].add(unblock[1])
                if filter:
                    filterDict[filter[0]] = filter[1]
        logger.info("%s: block=%d, unblock=%d, filter=%d"%(rule.name,len(blockDict),len(unblockDict),len(filterDict)))
        return blockDict,unblockDict,filterDict