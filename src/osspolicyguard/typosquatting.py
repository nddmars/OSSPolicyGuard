"""
OPG-046: Typosquatting similarity detection for npm and PyPI packages.

Uses only stdlib modules (re, unicodedata).
"""

from __future__ import annotations

import re
import unicodedata

__all__ = ["detect_typosquatting", "is_suspicious", "edit_distance"]

# ---------------------------------------------------------------------------
# Popular package sets
# ---------------------------------------------------------------------------

POPULAR_NPM: frozenset[str] = frozenset(
    {
        "react", "lodash", "express", "axios", "webpack", "typescript", "jest",
        "eslint", "prettier", "chalk", "next", "vue", "moment", "uuid", "dotenv",
        "commander", "inquirer", "semver", "glob", "minimatch", "path",
        "fs-extra", "cross-env", "nodemon", "ts-node", "esbuild", "rollup",
        "vite", "tailwindcss", "postcss", "sass", "socket.io", "fastify", "koa",
        "hapi", "sequelize", "prisma", "mongoose", "pg", "redis", "aws-sdk",
        "zod", "yup", "joi", "ajv", "cheerio", "puppeteer", "playwright",
        "sharp", "multer", "cors", "helmet", "morgan", "body-parser",
        "cookie-parser", "express-validator", "passport", "jsonwebtoken",
        "bcrypt", "crypto-js", "marked", "highlight.js",
    }
)

POPULAR_PYPI: frozenset[str] = frozenset(
    {
        "requests", "numpy", "pandas", "flask", "django", "fastapi", "sqlalchemy",
        "pydantic", "pytest", "boto3", "pillow", "click", "httpx", "aiohttp",
        "uvicorn", "gunicorn", "celery", "redis", "pymongo", "psycopg2",
        "cryptography", "paramiko", "yaml", "toml", "attrs", "jinja2", "arrow",
        "black", "flake8", "mypy", "pylint", "bandit", "safety", "scrapy",
        "beautifulsoup4", "lxml", "selenium", "playwright", "tensorflow", "torch",
        "scikit-learn", "matplotlib", "scipy", "statsmodels", "airflow",
        "kubernetes", "docker", "ansible", "fabric", "rich", "typer", "httpcore",
        "anyio", "starlette", "passlib", "python-jose", "alembic",
        "pydantic-settings", "python-dotenv", "loguru", "structlog",
    }
)

# ---------------------------------------------------------------------------
# String utility functions
# ---------------------------------------------------------------------------

def edit_distance(a: str, b: str) -> int:
    """Return the Levenshtein edit distance between *a* and *b*.

    Iterative O(m*n) dynamic-programming implementation; no recursion.
    """
    m, n = len(a), len(b)
    # Allocate (m+1) x (n+1) matrix
    dp = [[0] * (n + 1) for _ in range(m + 1)]

    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                dp[i][j] = dp[i - 1][j - 1]
            else:
                dp[i][j] = 1 + min(
                    dp[i - 1][j],      # deletion
                    dp[i][j - 1],      # insertion
                    dp[i - 1][j - 1],  # substitution
                )
    return dp[m][n]


def homoglyph_normalize(name: str) -> str:
    """Normalize *name* by replacing common homoglyphs used in typosquatting.

    Applies Unicode NFKC normalization first, then applies these substitutions:
      Character-level: 0->o, 1->l, 3->e, 4->a, 5->s, @->a
      String-level:    rn->m, vv->w, II->ll, l->l (identity; l stays l)
    """
    # Unicode normalization first to collapse look-alike code points
    name = unicodedata.normalize("NFKC", name)

    # Character-level substitutions
    _char_map: dict[str, str] = {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "@": "a",
    }
    result = "".join(_char_map.get(ch, ch) for ch in name)

    # Multi-character string substitutions (applied in order)
    result = result.replace("rn", "m")
    result = result.replace("vv", "w")
    result = result.replace("II", "ll")

    return result


def _separator_normalize(name: str) -> str:
    """Return *name* with all ``-``, ``_``, and ``.`` characters removed."""
    return re.sub(r"[-_.]", "", name)


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def detect_typosquatting(
    package_name: str,
    ecosystem: str,
    threshold: int = 2,
) -> list[dict]:
    """Detect whether *package_name* is likely a typosquat of a popular package.

    Parameters
    ----------
    package_name:
        The package name to evaluate.
    ecosystem:
        ``"npm"`` / ``"javascript"`` / ``"typescript"`` / ``"node"`` for npm, or
        ``"pypi"`` / ``"python"`` for PyPI.  Any other value returns ``[]``.
    threshold:
        Maximum Levenshtein distance that triggers an edit-distance match
        (default 2).

    Returns
    -------
    list[dict]
        Each entry contains:
        ``suspect``    - the evaluated package name,
        ``similar_to`` - the popular package it resembles,
        ``distance``   - Levenshtein distance between the two names,
        ``method``     - one of ``"edit_distance"``, ``"homoglyph"``,
                         ``"separator"``, ``"prefix"``.
        Returns ``[]`` when the package is itself in the popular set, when the
        ecosystem is unknown, or when no matches are found.  Results are
        deduplicated by ``similar_to``.
    """
    eco = ecosystem.lower()
    if eco in ("npm", "javascript", "typescript", "node"):
        popular = POPULAR_NPM
    elif eco in ("pypi", "python"):
        popular = POPULAR_PYPI
    else:
        return []

    # A package is not squatting itself
    if package_name in popular:
        return []

    results: list[dict] = []
    seen: set[str] = set()  # tracks similar_to values already added

    norm_suspect_homoglyph = homoglyph_normalize(package_name)
    norm_suspect_sep = _separator_normalize(package_name)

    for pkg in popular:
        if pkg in seen:
            continue

        # Compute edit distance once; reuse across later checks for the
        # distance field even when a different method triggers the match.
        dist = edit_distance(package_name, pkg)

        # 1. Edit-distance check
        if dist <= threshold:
            results.append(
                {
                    "suspect": package_name,
                    "similar_to": pkg,
                    "distance": dist,
                    "method": "edit_distance",
                }
            )
            seen.add(pkg)
            continue

        # 2. Homoglyph normalization check
        if norm_suspect_homoglyph == homoglyph_normalize(pkg):
            results.append(
                {
                    "suspect": package_name,
                    "similar_to": pkg,
                    "distance": dist,
                    "method": "homoglyph",
                }
            )
            seen.add(pkg)
            continue

        # 3. Separator normalization check
        if norm_suspect_sep == _separator_normalize(pkg):
            results.append(
                {
                    "suspect": package_name,
                    "similar_to": pkg,
                    "distance": dist,
                    "method": "separator",
                }
            )
            seen.add(pkg)
            continue

        # 4. Prefix check: package_name starts with pkg and is at least 2 chars longer
        if package_name.startswith(pkg) and len(package_name) >= len(pkg) + 2:
            results.append(
                {
                    "suspect": package_name,
                    "similar_to": pkg,
                    "distance": dist,
                    "method": "prefix",
                }
            )
            seen.add(pkg)
            continue

    return results


def is_suspicious(package_name: str, ecosystem: str) -> bool:
    """Return ``True`` if *package_name* appears to be a typosquat of a popular package."""
    return bool(detect_typosquatting(package_name, ecosystem))
