import os

GITHUB_OWNER = os.getenv("GITHUB_OWNER", "1314520lovelsc")
GITHUB_REPO = os.getenv("GITHUB_REPO", "adblockfilters")
GITHUB_BRANCH = os.getenv("GITHUB_BRANCH", "main")

GITHUB_HOME = f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}"
RAW_RULES_BASE = f"https://raw.githubusercontent.com/{GITHUB_OWNER}/{GITHUB_REPO}/{GITHUB_BRANCH}/rules"
JSDELIVR_GH_BASE = f"https://gcore.jsdelivr.net/gh/{GITHUB_OWNER}/{GITHUB_REPO}@{GITHUB_BRANCH}/rules"
PURGE_JSDELIVR_BASE = f"https://purge.jsdelivr.net/gh/{GITHUB_OWNER}/{GITHUB_REPO}@{GITHUB_BRANCH}/rules"
STAR_HISTORY_REPO = f"{GITHUB_OWNER}/{GITHUB_REPO}"
