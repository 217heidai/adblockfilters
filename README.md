# AdBlock DNS Filters
适用于AdGuard的去广告合并规则，每8个小时更新一次。
个人收藏了不少广告过滤规则，但是每次往新设备添加的时候很是头疼，于是写了这个项目，定时自动获取各规则源更新，生成合并规则库。

## 说明
1. 定时从上游各规则源获取更新，合并去重。
2. 使用国内、国外各 3 组 DNS 服务，分别对上游各规则源拦截的域名进行解析，去除已无法解析的域名。（上游各规则源中存在大量已无法解析的域名，无需加入拦截规则）
3. 本项目仅对上游规则进行合并、去重、去除无效域名，不做任何修改。如发现误拦截情况，可临时添加放行规则（如 `@@||www.example.com^$important`），并向上游规则反馈。

## 订阅链接
1. AdGuard Home 等 DNS 拦截服务使用规则1
2. AdGuard 等浏览器插件使用规则1 + 规则2（规则2为规则1的补充，仅适用浏览器插件）
3. InviZible Pro、personalDNSfilter 使用规则3（规则3与规则1拦截域名一致，仅格式差异）
4. DNSMasq 使用规则4（规则4与规则1拦截域名一致，仅格式差异）
5. 规则1’、2’、3’、4'为规则1、2、3、4的 Lite 版，仅针对国内域名拦截，体积较小（如添加完整规则报错数量限制，请尝试 Lite 规则）
6. 已对 jsdelivr 缓存进行主动刷新，但 jsdelivr 加速链接仍存在一定延时

| 规则 | 原始链接 | 加速链接1 | 加速链接2 | 适配说明 |
|:-|:-|:-|:-|:-|
| 规则1 | [原始链接](https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt) | [加速链接1](https://gcore.jsdelivr.net/gh/217heidai/adblockfilters@main/rules/adblockdns.txt) | [加速链接2](https://github.boki.moe/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt) | AdGuard、AdGuard Home 等 |
| 规则1' | [原始链接](https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt) | [加速链接1](https://gcore.jsdelivr.net/gh/217heidai/adblockfilters@main/rules/adblockdnslite.txt) | [加速链接2](https://github.boki.moe/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt) | AdGuard、AdGuard Home 等 |
| 规则2 | [原始链接](https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilters.txt) | [加速链接1](https://gcore.jsdelivr.net/gh/217heidai/adblockfilters@main/rules/adblockfilters.txt) | [加速链接2](https://github.boki.moe/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilters.txt) | AdGuard 等 |
| 规则2' | [原始链接](https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilterslite.txt) | [加速链接1](https://gcore.jsdelivr.net/gh/217heidai/adblockfilters@main/rules/adblockfilterslite.txt) | [加速链接2](https://github.boki.moe/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilterslite.txt) | AdGuard 等 |
| 规则3 | [原始链接](https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdomain.txt) | [加速链接1](https://gcore.jsdelivr.net/gh/217heidai/adblockfilters@main/rules/adblockdomain.txt) | [加速链接2](https://github.boki.moe/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdomain.txt) | InviZible Pro、personalDNSfilter |
| 规则3' | [原始链接](https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdomainlite.txt) | [加速链接1](https://gcore.jsdelivr.net/gh/217heidai/adblockfilters@main/rules/adblockdomainlite.txt) | [加速链接2](https://github.boki.moe/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdomainlite.txt) | InviZible Pro、personalDNSfilter |
| 规则4 | [原始链接](https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnsmasq.txt) | [加速链接1](https://gcore.jsdelivr.net/gh/217heidai/adblockfilters@main/rules/adblockdnsmasq.txt) | [加速链接2](https://github.boki.moe/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnsmasq.txt) | DNSMasq |
| 规则4' | [原始链接](https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnsmasqlite.txt) | [加速链接1](https://gcore.jsdelivr.net/gh/217heidai/adblockfilters@main/rules/adblockdnsmasqlite.txt) | [加速链接2](https://github.boki.moe/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnsmasqlite.txt) | DNSMasq |

## 上游规则源
1. 感谢各位广告过滤规则维护大佬们的辛苦付出。
2. 不再引用[anti-AD](https://anti-ad.net/adguard.txt)、[yhosts](https://raw.githubusercontent.com/VeleSila/yhosts/master/hosts.txt)，具体原因见[Mosney/anti-anti-AD](https://github.com/Mosney/anti-anti-AD)。
3. 移除[Notracking blocklist](https://raw.githubusercontent.com/notracking/hosts-blocklists/master/adblock/adblock.txt)，原项目[已停止维护](https://github.com/notracking/hosts-blocklists/issues/900)。
4. 移除[ADgk](https://raw.githubusercontent.com/banbendalao/ADgk/master/ADgk.txt)，项目超过 1 年未更新。
5. 不再引用[NEO DEV HOST](https://github.com/neodevpro/neodevhost/blob/master/lite_adblocker)，原因见[Issues 85](https://github.com/217heidai/adblockfilters/issues/85)。

| 规则 | 类型 | 原始链接 | 加速链接1 | 加速链接2 | 更新日期 |
|:-|:-|:-|:-|:-|:-|
| AdGuard Base filter | filter | [原始链接](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt) | [加速链接1](https://gcore.jsdelivr.net/gh/217heidai/adblockfilters@main/rules/AdGuard_Base_filter.txt) | [加速链接2](https://github.boki.moe/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AdGuard_Base_filter.txt) | 2024/12/25 |
| AdGuard Chinese filter | filter | [原始链接](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt) | [加速链接1](https://gcore.jsdelivr.net/gh/217heidai/adblockfilters@main/rules/AdGuard_Chinese_filter.txt) | [加速链接2](https://github.boki.moe/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AdGuard_Chinese_filter.txt) | 2024/12/25 |
| AdGuard Mobile Ads filter | filter | [原始链接](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt) | [加速链接1](https://gcore.jsdelivr.net/gh/217heidai/adblockfilters@main/rules/AdGuard_Mobile_Ads_filter.txt) | [加速链接2](https://github.boki.moe/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AdGuard_Mobile_Ads_filter.txt) | 2024/12/07 |
| AdGuard DNS filter | filter | [原始链接](https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt) | [加速链接1](https://gcore.jsdelivr.net/gh/217heidai/adblockfilters@main/rules/AdGuard_DNS_filter.txt) | [加速链接2](https://github.boki.moe/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AdGuard_DNS_filter.txt) | 2024/12/25 |
| AdRules DNS List | filter | [原始链接](https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt) | [加速链接1](https://gcore.jsdelivr.net/gh/217heidai/adblockfilters@main/rules/AdRules_DNS_List.txt) | [加速链接2](https://github.boki.moe/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AdRules_DNS_List.txt) | 2024/12/25 |
| CJX's Annoyance List | filter | [原始链接](https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt) | [加速链接1](https://gcore.jsdelivr.net/gh/217heidai/adblockfilters@main/rules/CJX's_Annoyance_List.txt) | [加速链接2](https://github.boki.moe/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/CJX's_Annoyance_List.txt) | 2024/12/22 |
| EasyList | filter | [原始链接](https://easylist-downloads.adblockplus.org/easylist.txt) | [加速链接1](https://gcore.jsdelivr.net/gh/217heidai/adblockfilters@main/rules/EasyList.txt) | [加速链接2](https://github.boki.moe/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/EasyList.txt) | 2024/12/25 |
| EasyList China | filter | [原始链接](https://easylist-downloads.adblockplus.org/easylistchina.txt) | [加速链接1](https://gcore.jsdelivr.net/gh/217heidai/adblockfilters@main/rules/EasyList_China.txt) | [加速链接2](https://github.boki.moe/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/EasyList_China.txt) | 2024/12/25 |
| EasyPrivacy | filter | [原始链接](https://easylist-downloads.adblockplus.org/easyprivacy.txt) | [加速链接1](https://gcore.jsdelivr.net/gh/217heidai/adblockfilters@main/rules/EasyPrivacy.txt) | [加速链接2](https://github.boki.moe/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/EasyPrivacy.txt) | 2024/12/25 |
| xinggsf mv | filter | [原始链接](https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt) | [加速链接1](https://gcore.jsdelivr.net/gh/217heidai/adblockfilters@main/rules/xinggsf_mv.txt) | [加速链接2](https://github.boki.moe/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/xinggsf_mv.txt) | 2024/12/17 |
| xinggsf rule | filter | [原始链接](https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/rule.txt) | [加速链接1](https://gcore.jsdelivr.net/gh/217heidai/adblockfilters@main/rules/xinggsf_rule.txt) | [加速链接2](https://github.boki.moe/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/xinggsf_rule.txt) | 2024/11/17 |
| jiekouAD | filter | [原始链接](https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt) | [加速链接1](https://gcore.jsdelivr.net/gh/217heidai/adblockfilters@main/rules/jiekouAD.txt) | [加速链接2](https://github.boki.moe/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/jiekouAD.txt) | 2024/12/21 |
| 1Hosts (Lite) | dns | [原始链接](https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/adblock.txt) | [加速链接1](https://gcore.jsdelivr.net/gh/217heidai/adblockfilters@main/rules/1Hosts_(Lite).txt) | [加速链接2](https://github.boki.moe/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/1Hosts_(Lite).txt) | 2024/12/16 |
| AWAvenue Ads Rule | dns | [原始链接](https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt) | [加速链接1](https://gcore.jsdelivr.net/gh/217heidai/adblockfilters@main/rules/AWAvenue_Ads_Rule.txt) | [加速链接2](https://github.boki.moe/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AWAvenue_Ads_Rule.txt) | 2024/12/22 |
| DNS-Blocklists Light | dns | [原始链接](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt) | [加速链接1](https://gcore.jsdelivr.net/gh/217heidai/adblockfilters@main/rules/DNS-Blocklists_Light.txt) | [加速链接2](https://github.boki.moe/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/DNS-Blocklists_Light.txt) | 2024/12/25 |
| Hblock | dns | [原始链接](https://hblock.molinero.dev/hosts_adblock.txt) | [加速链接1](https://gcore.jsdelivr.net/gh/217heidai/adblockfilters@main/rules/Hblock.txt) | [加速链接2](https://github.boki.moe/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/Hblock.txt) | 2024/12/24 |
| OISD Basic | dns | [原始链接](https://abp.oisd.nl/basic/) | [加速链接1](https://gcore.jsdelivr.net/gh/217heidai/adblockfilters@main/rules/OISD_Basic.txt) | [加速链接2](https://github.boki.moe/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/OISD_Basic.txt) | 2024/12/25 |
| SmartTV Blocklist | dns | [原始链接](https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV-AGH.txt) | [加速链接1](https://gcore.jsdelivr.net/gh/217heidai/adblockfilters@main/rules/SmartTV_Blocklist.txt) | [加速链接2](https://github.boki.moe/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/SmartTV_Blocklist.txt) | 2023/10/11 |
| 1024 hosts | host | [原始链接](https://raw.githubusercontent.com/Goooler/1024_hosts/master/hosts) | [加速链接1](https://gcore.jsdelivr.net/gh/217heidai/adblockfilters@main/rules/1024_hosts.txt) | [加速链接2](https://github.boki.moe/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/1024_hosts.txt) | 2023/08/31 |
| ad-wars hosts | host | [原始链接](https://raw.githubusercontent.com/jdlingyu/ad-wars/master/hosts) | [加速链接1](https://gcore.jsdelivr.net/gh/217heidai/adblockfilters@main/rules/ad-wars_hosts.txt) | [加速链接2](https://github.boki.moe/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/ad-wars_hosts.txt) | 2023/11/17 |
| StevenBlack hosts | host | [原始链接](https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts) | [加速链接1](https://gcore.jsdelivr.net/gh/217heidai/adblockfilters@main/rules/StevenBlack_hosts.txt) | [加速链接2](https://github.boki.moe/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/StevenBlack_hosts.txt) | 2024/12/24 |

## Star History
[![Star History Chart](https://api.star-history.com/svg?repos=217heidai/adblockfilters&type=Date)](https://star-history.com/#217heidai/adblockfilters&Date)
