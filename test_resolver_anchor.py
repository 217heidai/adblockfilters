# _resolveDNS 锚定放行规则回归自检，无需联网
# 用法：python3 test_resolver_anchor.py
import os
import shutil
import tempfile

from readme import Rule
from resolver import Resolver

# 上游 AdGuard DNS filter 的实际写法：整域拦截，但锚定放行其中一个子域
#   ||nitropay.com^
#   @@||sponsor.nitropay.com^|
tmp = tempfile.mkdtemp()
try:
    with open(os.path.join(tmp, 't.txt'), 'w') as f:
        f.write('||nitropay.com^\n')
        f.write('@@||sponsor.nitropay.com^|\n')

    blockDict, unblockDict, filterDict = Resolver(tmp).resolveDNS(Rule('t', 'dns', '', ''))

    assert 'nitropay.com' in blockDict, blockDict
    assert 'sponsor' in unblockDict.get('nitropay.com', set()), unblockDict
finally:
    shutil.rmtree(tmp)

print('ok')
