# AdBlock DNS Filters
适用于AdGuard的去广告合并规则，每8个小时更新一次。
个人收藏了不少广告过滤规则，但是每次往新设备添加的时候很是头疼，于是写了这个项目，定时自动获取各规则源更新，生成合并规则库。

## 说明
1. 定时从上游各规则源获取更新，合并去重。
2. 使用国内、国外各 3 组 DNS 服务，分别对上游各规则源拦截的域名进行解析，去除已无法解析的域名。（上游各规则源中存在大量已无法解析的域名，无需加入拦截规则）
3. 本项目仅对上游规则进行合并、去重、去除无效域名，不做任何修改。如发现误拦截情况，可临时添加放行规则（如 `@@||www.example.com^$important`），并向上游规则反馈。

## 订阅链接
1. AdGuard Home 等 DNS 拦截服务使用规则1
2. AdGuard 等浏览器插件使用规则1 + 规则2
3. 规则1’、规则2’为相应的 Lite 版，仅针对国内域名拦截

| 规则 | 原始链接 | 加速链接 |
|:-|:-|:-|
| 规则1：DNS 拦截 | [原始链接](https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt) |
| 规则1'：DNS 拦截 Lite | [原始链接](https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt) |
| 规则2：插件拦截 | [原始链接](https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilters.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilters.txt) |
| 规则2'：插件拦截 Lite | [原始链接](https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilterslite.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilterslite.txt) |

## 上游规则源
1. 感谢各位广告过滤规则维护大佬们的辛苦付出。
2. 不再引用[anti-AD](https://anti-ad.net/adguard.txt)、[yhosts](https://raw.githubusercontent.com/VeleSila/yhosts/master/hosts.txt)，具体原因见[Mosney/anti-anti-AD](https://github.com/Mosney/anti-anti-AD)。
3. 移除[Notracking blocklist](https://raw.githubusercontent.com/notracking/hosts-blocklists/master/adblock/adblock.txt)，原项目[已停止维护](https://github.com/notracking/hosts-blocklists/issues/900)。
4. 移除[ADgk](https://raw.githubusercontent.com/banbendalao/ADgk/master/ADgk.txt)，项目超过 1 年未更新。

| 规则 | 类型 | 原始链接 | 加速链接 | 更新日期 |
|:-|:-|:-|:-|:-|
| damengzhu filter | filter | [原始链接](https://raw.githubusercontent.com/damengzhu/abpmerge/refs/heads/main/CSSRule.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/damengzhu_filter.txt) | 2024/10/26 |
| ADgk filter | filter | [原始链接](https://raw.githubusercontent.com/banbendalao/ADgk/master/ADgk.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/ADgk_filter.txt) | 2024/10/26 |
| AdGuard Chinese filter | filter | [原始链接](https://filters.adtidy.org/extension/ublock/filters/224.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AdGuard_Chinese_filter.txt) | 2024/10/26 |
| AdGuard URL Tracking filter | filter | [原始链接](https://filters.adtidy.org/extension/ublock/filters/17.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AdGuard_URL_Tracking_filter.txt) | 2024/10/26 |
| LegitimateURLShortener | filter | [原始链接](https://raw.githubusercontent.com/DandelionSprout/adfilt/master/LegitimateURLShortener.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/LegitimateURLShortener.txt) | 2024/10/26 |
| AdGuard Tracking Protection lite filter | filter | [原始链接](https://filters.adtidy.org/ios/filters/3_optimized.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AdGuard_Tracking_Protection_lite_filter.txt) | 2024/10/26 |
| privacy filter | filter | [原始链接](https://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/thirdparties/easyprivacy.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/privacy_filter.txt) | 2024/10/26 |
| ph00lt0 filter | filter | [原始链接](https://raw.githubusercontent.com/ph00lt0/blocklists/master/blocklist.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/ph00lt0_filter.txt) | 2024/10/26 |
| YanFung Mobile filter | filter | [原始链接](https://raw.githubusercontent.com/YanFung/Ads/master/Mobile) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/YanFung_Mobile_filter.txt) | 2024/10/26 |
| Adfilter | filter | [原始链接](https://raw.githubusercontent.com/vokins/ad/main/ab.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/Adfilter.txt) | 2024/10/26 |
| NoAppDownload | filter | [原始链接](https://raw.githubusercontent.com/Noyllopa/NoAppDownload/master/NoAppDownload.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/NoAppDownload.txt) | 2024/10/26 |
| Ad Filter J | filter | [原始链接](https://raw.githubusercontent.com/jk278/Ad-J/main/Ad-J.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/Ad_Filter_J.txt) | 2024/10/26 |
| jiekouAD | filter | [原始链接](https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/jiekouAD.txt) | 2024/10/24 |
| AdGuard Widgets filter | filter | [原始链接](https://filters.adtidy.org/extension/ublock/filters/22_optimized.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AdGuard_Widgets_filter.txt) | 2024/10/26 |
| AdGuard Social Media filter | filter | [原始链接](https://filters.adtidy.org/extension/ublock/filters/4_optimized.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AdGuard_Social_Media_filter.txt) | 2024/10/26 |
| AdGuard Popups filter | filter | [原始链接](https://filters.adtidy.org/extension/ublock/filters/19_optimized.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AdGuard_Popups_filter.txt) | 2024/10/26 |
| AdGuard Other Annoyances filter | filter | [原始链接](https://filters.adtidy.org/extension/ublock/filters/21_optimized.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AdGuard_Other_Annoyances_filter.txt) | 2024/10/26 |
| AdGuard Mobile App Banners  filter | filter | [原始链接](https://filters.adtidy.org/extension/ublock/filters/20_optimized.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AdGuard_Mobile_App_Banners__filter.txt) | 2024/10/26 |

## Star History
[![Star History Chart](https://api.star-history.com/svg?repos=217heidai/adblockfilters&type=Date)](https://star-history.com/#217heidai/adblockfilters&Date)
