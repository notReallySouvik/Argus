# --- Network / Timeouts ---
DEFAULT_HTTP_TIMEOUT = 8.0
DEFAULT_PROBE_TIMEOUT = 5.0
DEFAULT_DNS_LIFETIME = 5.0
DEFAULT_DNS_TIMEOUT = 3.0

# --- Output ---
DEFAULT_OUTPUT_DIR = "reports"
JSON_REPORT_NAME = "findings.json"
CSV_REPORT_NAME = "assets.csv"
HTML_REPORT_NAME = "report.html"

# --- Recon Data ---
COMMON_SUBDOMAINS = [
    "www",
    "api",
    "app",
    "dev",
    "staging",
    "test",
    "admin",
    "portal",
    "mail",
    "vpn",
]

# --- Risk Signal Keywords ---
ADMIN_KEYWORDS = ["admin", "dashboard", "control", "panel"]
NON_PROD_KEYWORDS = ["dev", "staging", "test", "qa", "beta"]
BACKUP_KEYWORDS = ["backup", "bak", "snapshot"]
INTERNAL_KEYWORDS = ["internal", "intra", "corp", "staff"]
LEGACY_KEYWORDS = ["old", "legacy", "deprecated", "v1-old"]

LOGIN_KEYWORDS = ["login", "signin", "sign in", "auth"]
ADMIN_PANEL_KEYWORDS = ["admin", "dashboard", "control panel", "console"]

# --- Status Heuristics ---
UNEXPECTED_STATUS_CODES = {401, 403, 500, 502, 503}

# --- Web Heuristics ---
DEFAULT_PAGE_MARKERS = [
    "welcome to nginx",
    "apache2 ubuntu default page",
    "iis windows server",
    "test page for apache",
]

DIRECTORY_LISTING_MARKERS = [
    "index of /",
    "directory listing for",
]

ERROR_PAGE_MARKERS = [
    "internal server error",
    "bad gateway",
    "service unavailable",
    "application error",
]

# --- Confidence Defaults ---
CONFIDENCE_PRIMARY = 0.95
CONFIDENCE_SECONDARY = 0.70

# --- HTTP ---
USER_AGENT = "Argus/0.2"

# --- Discovery Confidence ---
SOURCE_CONFIDENCE = {
    "wordlist": 0.55,
    "crtsh": 0.80,
    "manual": 0.95,
}

# --- Common Ports ---
COMMON_PORTS = {
    21: ("ftp", "file_transfer"),
    22: ("ssh", "remote_admin"),
    25: ("smtp", "mail"),
    53: ("dns", "infrastructure"),
    80: ("http", "web"),
    110: ("pop3", "mail"),
    143: ("imap", "mail"),
    443: ("https", "web"),
    445: ("smb", "file_sharing"),
    3306: ("mysql", "database"),
    3389: ("rdp", "remote_admin"),
    5432: ("postgresql", "database"),
    6379: ("redis", "database"),
    8080: ("http-alt", "web"),
    8443: ("https-alt", "web"),
}

DEFAULT_PORT_TIMEOUT = 1.5