import os

from loguru import logger

from readme import ReadMe
from updater import Updater
from filter import Filter

class ADBlock(object):
    def __init__(self):
        self.pwd = os.getcwd()

    def refresh(self):
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
        # 更新上游规
        updater = Updater(ruleList)
        update, ruleList = updater.update(self.pwd + '/rules')
        if not update:
            return
        
        # 生成新规则
        filter = Filter(ruleList, self.pwd + '/rules')
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
    adBlock = ADBlock()
    adBlock.refresh()