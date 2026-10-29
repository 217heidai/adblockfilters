import os

from loguru import logger
from tld.utils import update_tld_names

from readme import ReadMe
from updater import Updater
from filter import Filter

class ADBlock(object):
    def __init__(self):
        self.pwd = os.getcwd()
        self.cacheDir = os.path.join(self.pwd, '.cache')
        self.sourceDir = os.path.join(self.cacheDir, 'source')   # 上游规则源下载目录
        self.outDir    = os.path.join(self.cacheDir, 'out')       # 生成产物目录
        self.domainDir = os.path.join(self.cacheDir, 'domain')    # black/china/white/myblock/domain.txt

    def refresh(self):
        for d in (self.sourceDir, self.outDir, self.domainDir):
            os.makedirs(d, exist_ok=True)

        readme = ReadMe(self.pwd + '/README.md')
        ruleList = readme.getRules()
        '''
        # for test
        testList = []
        for rule in ruleList:
            if rule.type in ['filter']:
                testList.append(rule)
        #    if rule.name in ["AdGuard Mobile Ads filter"]: # "AdRules DNS List", "CJX's Annoyance List", "EasyList China", "EasyList", "EasyPrivacy", "jiekouAD", "xinggsf mv", "xinggsf rule"
        #        testList.append(rule)
        ruleList = testList
        '''
        # 更新上游规则（下载到 .cache/source）
        updater = Updater(ruleList)
        update, ruleList = updater.update(self.sourceDir)
        if not update:
            return

        # 生成新规则（读 .cache/domain，输出 .cache/out）
        filter = Filter(ruleList, self.domainDir, self.outDir, self.sourceDir)
        filter.generate(readme.getRulesNames())

        # 生成 readme.md
        readme.setRules(ruleList)
        readme.regenerate()

if __name__ == '__main__':
    '''
    # for test
    logFile = os.getcwd() + "/adblock.log"
    if os.path.exists(logFile):
        os.remove(logFile)
    logger.add(logFile)
    '''
    # 更新 tld
    update_tld_names()

    adBlock = ADBlock()
    adBlock.refresh()
