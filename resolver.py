import os
import re

class Resolver(object):
    def __init__(self, fileName):
        self.__fileName = fileName

    def Resolve(self):
        def match(pattern, string):
            matchObj = re.match(pattern, string)
            if matchObj:
                    #print(matchObj.group())
                    return True
            return False

        blockList = []
        unblockList = []
        if not os.path.exists(self.__fileName):
            return blockList,unblockList
        with open(self.__fileName, "r") as f:
            for line in f:
                # 去掉换行符
                line = line.replace('\r', '').replace('\n', '').strip()
                # 去掉空行
                if len(line) < 1:
                    continue
                # 跳过注释! #
                if match('^!.*', line) or match('^#.*', line):
                    continue
                # 跳过注释[]
                if line.find('[') == 0 and line.rfind(']')== len(line)-1:
                    continue
                # ||
                if match('^\|\|.*', line):
                    #print(line)
                    blockList.append(line)
                    continue
                # /REGEX/
                if match('^/.*', line):
                    #print(line)
                    blockList.append(line)
                    continue
                # @@
                if match('^@@.*', line):
                    #print(line)
                    unblockList.append(line)
                    continue

                # @ 注释
                if match('^@.*', line):
                    #print(line)
                    continue

                # host 模式
                if line.find('0.0.0.0')==0 or line.find('127.0.0.1') == 0:
                    row = line.split(' ')
                    row = list(map(lambda x: x.strip(), row)) # 字段去空格
                    for i in range(len(row)-1):
                        if len(row[i]) == 0:
                            row.pop(i)
                    domain = row[1]
                    if domain in ['localhost', 'localhost.localdomain', 'local', '0.0.0.0']:
                        continue
                    domain = '||%s^'%(domain)
                    blockList.append(domain)
                    continue

                # 过滤无效的hosts
                if line.replace(' ', '') in ['::1localhost','255.255.255.255broadcasthost','::1ip6-localhost','::1ip6-loopback','fe80::1%lo0localhost','ff00::0ip6-localnet','ff00::0ip6-mcastprefix','ff02::1ip6-allnodes','ff02::2ip6-allrouters','ff02::3ip6-allhosts','255.255.255.255\tbroadcasthost']:
                    continue

                blockList.append(line)
                pass
        return blockList,unblockList        
if __name__ == '__main__':
    pwd = os.getcwd()
    file = pwd + '/rules/Hblock_Filters.txt'
    resolver = Resolver(file)
    blockList, unblockList = resolver.Resolve()
    print('blockList: %s'%(len(blockList)))
    print('unblockList: %s'%(len(unblockList)))