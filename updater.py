import os
import re
import time
import hashlib
import email.utils
import asyncio
from datetime import datetime
from typing import List,Tuple

import httpx
from loguru import logger

from readme import Rule

# 上游规则更新
class Updater(object):
    def __init__(self, ruleList:List[Rule]):
        self.ruleList = ruleList
        self.isNeedUpdate = False

    def update(self, path:str) -> Tuple[bool,List[Rule]]:
        async def _update():
            # 限制 GitHub API 查询并发（配合无认证限流）
            self._apiSem = asyncio.Semaphore(4)
            # 并发执行所有下载任务，并直接拿到结果
            tasks = [self.__Download(rule, path) for rule in self.ruleList]
            results = await asyncio.gather(*tasks)

            # 更新规则状态
            for new in results:
                for rule in self.ruleList:
                    if new.name == rule.name:
                        rule.latest = new.latest
                        rule.update = new.update
                        if rule.update:
                            self.isNeedUpdate = True   # 只要有一个需要更新就标记
                        break
            return self.isNeedUpdate, self.ruleList

        return asyncio.run(_update())

    def __CalcFileSha256(self, filename):
        with open(filename, "rb") as f:
            sha256obj = hashlib.sha256()
            sha256obj.update(f.read())
            hash_value = sha256obj.hexdigest()
            return hash_value

    def __ParseDate(self, value: str):
        """解析 RFC 2822（Last-Modified）或 ISO 8601（GitHub API）日期，返回 aware datetime，失败返回 None"""
        if not value:
            return None
        try:
            return email.utils.parsedate_to_datetime(value)
        except Exception:
            pass
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except Exception:
            return None

    async def __QueryLastModified(self, url: str) -> str:
        """查询 raw.githubusercontent.com 文件的最后修改日期（返回 YYYY/MM/DD，失败返回空串）
        优先 GitHub API（带 GITHUB_TOKEN），403/失败回退 GitHub commits .atom 网页端点（无 API 限流）"""
        match = re.match(r"https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)", url)
        if not match:
            return ""
        owner, repo, branch, path = match.group(1), match.group(2), match.group(3), match.group(4)

        dt = await self.__QueryApiDate(owner, repo, branch, path)
        if dt:
            return dt
        dt = await self.__QueryAtomDate(owner, repo, branch, path)
        if dt:
            return dt
        return ""

    async def __QueryApiDate(self, owner: str, repo: str, branch: str, path: str) -> str:
        api = "https://api.github.com/repos/%s/%s/commits?path=%s&sha=%s&per_page=1" % (owner, repo, path, branch)
        headers = {"Accept": "application/vnd.github+json"}
        token = os.environ.get("GITHUB_TOKEN", "")
        if token:
            headers["Authorization"] = "token " + token
        try:
            sem = getattr(self, "_apiSem", None)
            if sem is not None:
                await sem.acquire()
            try:
                async with httpx.AsyncClient() as client:
                    resp = await client.get(api, headers=headers)
                    if resp.status_code == 200:
                        data = resp.json()
                        if data:
                            dt = self.__ParseDate(data[0]["commit"]["committer"]["date"])
                            if dt:
                                return dt.astimezone().strftime("%Y/%m/%d")
                    elif resp.status_code == 403:
                        logger.warning("query api 403（限流或权限不足）, 回退 atom: %s/%s %s" % (owner, repo, path))
                    else:
                        logger.error(f'query api http %s: %s' % (resp.status_code, api))
            finally:
                if sem is not None:
                    sem.release()
        except Exception as e:
            logger.error(f'query api failed: %s [%s] %s' % (api, type(e).__name__, e))
        return ""

    async def __QueryAtomDate(self, owner: str, repo: str, branch: str, path: str) -> str:
        url = "https://github.com/%s/%s/commits/%s/%s.atom" % (owner, repo, branch, path)
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    m = re.search(r"<updated>([^<]+)</updated>", resp.text)
                    if m:
                        dt = self.__ParseDate(m.group(1))
                        if dt:
                            return dt.astimezone().strftime("%Y/%m/%d")
                else:
                    logger.error(f'query atom http %s: %s' % (resp.status_code, url))
        except Exception as e:
            logger.error(f'query atom failed: %s [%s] %s' % (url, type(e).__name__, e))
        return ""

    async def __Download(self, rule:Rule, path:str) -> Rule:
        fileName = path + "/" + rule.filename
        fileName_download = fileName + '.download'
        try:
            if os.path.exists(fileName_download):
                os.remove(fileName_download)

            async with httpx.AsyncClient() as client:
                response = await client.get(rule.url)
                response.raise_for_status()
                contentType = response.headers.get("Content-Type")
                if contentType.find("text/plain") < 0:
                    raise Exception("Content-Type[%s] error"%(contentType))
                lastModified = response.headers.get("Last-Modified")
                with open(fileName_download,'wb') as f:
                    f.write(response.content)

            if os.path.exists(fileName):
                sha256Old = self.__CalcFileSha256(fileName)
                sha256New = self.__CalcFileSha256(fileName_download)
                if sha256New != sha256Old:
                    rule.update = True
                os.remove(fileName)
            else:
                rule.update = True

            os.rename(fileName_download, fileName)

            # 更新日期优先级：上游 Last-Modified > GitHub API(raw源最后 commit) > 内容变化当天
            if lastModified:
                dt = self.__ParseDate(lastModified)
                if dt:
                    rule.latest = dt.astimezone().strftime("%Y/%m/%d")
                else:
                    qdate = await self.__QueryLastModified(rule.url)
                    if qdate:
                        rule.latest = qdate
                    elif rule.update:
                        rule.latest = time.strftime("%Y/%m/%d", time.localtime())
            else:
                qdate = await self.__QueryLastModified(rule.url)
                if qdate:
                    rule.latest = qdate
                elif rule.update:
                    rule.latest = time.strftime("%Y/%m/%d", time.localtime())
            logger.info("%s: latest=%s, update=%s"%(rule.name,rule.latest,rule.update))
            return rule
        except Exception as e:
            logger.error(f'%s download failed: %s' % (rule.name, e))
            return rule