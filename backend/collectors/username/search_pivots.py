"""
Generates a small set of search-engine URLs for manually pivoting on a
username. This makes zero network requests -- it just builds links for the
person to open and read themselves, same as a "search this" button.

Deliberately a trimmed set. The tool this idea came from (Ciberbrigada's
cb-userhunter) includes several more targeted templates -- resume/CV,
phone number, "password OR leak" -- that are built specifically to help
assemble a fuller personal dossier on someone rather than just surface
more public presence. Those are left out here; what's kept is limited to
generic identity/presence pivots.

Yielded with status "info" rather than found/not_found/error/unknown --
these aren't check results, just reference links, and the frontend renders
them in their own section rather than alongside confirmed hits.
"""
import urllib.parse
from typing import AsyncIterator, Dict, Any

from backend.collectors.base import BaseCollector

DORKS = [
    ("Exact match", '"{username}"'),
    ("@mention", '"@{username}"'),
    ("LinkedIn", '"{username}" site:linkedin.com'),
    ("GitHub", '"{username}" site:github.com'),
    ("Pastebin", 'intext:"{username}" site:pastebin.com'),
    ("PDF documents", '"{username}" filetype:pdf'),
]


class SearchPivotCollector(BaseCollector):
    name = "search_pivots"
    target_type = "username"

    def estimate(self, indicator: str, **kwargs) -> int:
        return len(DORKS)

    async def run(self, indicator: str, **kwargs) -> AsyncIterator[Dict[str, Any]]:
        username = indicator.strip()
        for label, template in DORKS:
            query = template.format(username=username)
            url = f"https://www.google.com/search?q={urllib.parse.quote(query)}"
            yield {
                "source": label,
                "category": "manual_search",
                "status": "info",
                "url": url,
                "details": {"query": query},
            }
