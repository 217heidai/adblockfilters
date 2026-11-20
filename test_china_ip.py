# _ip_in_ranges 最小自检：边界 + 已知 IP，无需联网
# 用法：python3 test_china_ip.py
from blacklist import _ip_in_ranges

# 10.0.0.0/8 -> [167772160, 184549375], 192.168.0.0/16 -> [3232235520, 3232301055]
starts = [167772160, 3232235520]
ends = [184549375, 3232301055]

assert _ip_in_ranges(167772161, starts, ends) is True    # 10.0.0.1
assert _ip_in_ranges(167772160, starts, ends) is True    # 区间起始
assert _ip_in_ranges(184549375, starts, ends) is True    # 区间结束
assert _ip_in_ranges(184549376, starts, ends) is False   # 刚过结束
assert _ip_in_ranges(3232235521, starts, ends) is True   # 192.168.0.1
assert _ip_in_ranges(134744072, starts, ends) is False   # 8.8.8.8
assert _ip_in_ranges(0, starts, ends) is False
print("ok")
