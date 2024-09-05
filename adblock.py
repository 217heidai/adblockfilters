import os

from readme import ReadMe
from updater import Updater
from filter import Filter

class ADBlock(object):
    def __init__(self):
        self.pwd = os.getcwd()

    def refresh(self):
        readme = ReadMe(self.pwd + '/README.md')
        ruleList = readme.getRules()
        
        # 更新上游规
        updater = Updater(ruleList)
        update, ruleList = updater.update(self.pwd + '/rules')
        if not update:
            return

        # 生成新规则
        filter = Filter(ruleList, self.pwd + '/rules')
        filter.generate()

        # 生成 readme.md
        readme.setRules(ruleList)
        readme.regenerate()

if __name__ == '__main__':
    adBlock = ADBlock()
    adBlock.refresh()