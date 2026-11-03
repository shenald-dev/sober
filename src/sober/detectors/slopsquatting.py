"""
Slopsquatting & Typosquatting Similarity Engine.
Identifies suspicious package imports that closely mimic legitimate top-tier
libraries (e.g. 'reqeusts' vs 'requests', 'nummpy' vs 'numpy') to defend against
supply-chain attacks targeting AI hallucinations.
"""

# Top popular Python packages frequently targeted by slopsquatting
POPULAR_PYTHON_PACKAGES: set[str] = {
    "requests", "numpy", "pandas", "urllib3", "setuptools", "wheel",
    "pip", "typing-extensions", "pydantic", "fastapi", "flask", "boto3",
    "botocore", "certifi", "idna", "charset-normalizer", "six", "pyyaml",
    "pytest", "click", "attrs", "jinja2", "cryptography", "python-dateutil",
    "s3transfer", "packaging", "markupsafe", "aiohttp", "sqlalchemy", "pytz",
    "scipy", "scikit-learn", "torch", "tensorflow", "httpx", "rich", "typer",
    "colorama", "tqdm", "matplotlib", "protobuf", "psutil", "dotenv",
    "python-dotenv", "celery", "redis", "pillow", "pymongo", "beautifulsoup4",
}

# Top popular npm packages frequently targeted by slopsquatting
POPULAR_NPM_PACKAGES: set[str] = {
    "react", "react-dom", "axios", "lodash", "express", "tslib", "chalk",
    "commander", "typescript", "vue", "next", "webpack", "vite", "moment",
    "dayjs", "zod", "prettier", "eslint", "dotenv", "glob", "fs-extra",
    "cors", "uuid", "debug", "rxjs", "inquirer", "semver", "rimraf",
    "body-parser", "jsonwebtoken", "bcrypt", "mongoose", "tailwindcss",
}


def damerau_levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate the Damerau-Levenshtein distance between two strings."""
    len1, len2 = len(s1), len(s2)
    d = [[0] * (len2 + 1) for _ in range(len1 + 1)]

    for i in range(len1 + 1):
        d[i][0] = i
    for j in range(len2 + 1):
        d[0][j] = j

    for i in range(1, len1 + 1):
        for j in range(1, len2 + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            d[i][j] = min(
                d[i - 1][j] + 1,       # deletion
                d[i][j - 1] + 1,       # insertion
                d[i - 1][j - 1] + cost  # substitution
            )
            # Transposition check
            if i > 1 and j > 1 and s1[i - 1] == s2[j - 2] and s1[i - 2] == s2[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)

    return d[len1][len2]


def find_slopsquatted_target(package_name: str, ecosystem: str = "python") -> tuple[str | None, int]:
    """
    Check if a package name is suspiciously close (distance 1 or 2) to a popular package,
    indicating a typosquatted or slopsquatted dependency hallucinated by an AI.
    """
    clean_name = package_name.lower().replace("_", "-").strip()
    popular_set = POPULAR_PYTHON_PACKAGES if ecosystem == "python" else POPULAR_NPM_PACKAGES

    if clean_name in popular_set:
        return None, 0

    best_target = None
    min_distance = 999

    for pop in popular_set:
        # Optimization: skip if length difference is greater than 2
        if abs(len(clean_name) - len(pop)) > 2:
            continue

        dist = damerau_levenshtein_distance(clean_name, pop)
        # Distance 1 or 2 indicates severe typosquatting risk
        if 0 < dist <= 2 and dist < min_distance:
            min_distance = dist
            best_target = pop

    if best_target and min_distance <= 2:
        return best_target, min_distance

    return None, 0
