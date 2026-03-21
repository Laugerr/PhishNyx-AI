URGENT_WORDS = [
    "urgent", "immediately", "asap", "action required", "verify now"
]

CREDENTIAL_WORDS = [
    "password", "login", "verify account", "reset", "confirm identity"
]

PAYMENT_WORDS = [
    "invoice",
    "payment",
    "wire transfer",
    "bank transfer",
    "payment overdue",
    "remittance",
]

ATTACHMENT_WORDS = [
    "attached invoice",
    "open the attachment",
    "attached document",
    "download the file",
    "see attached",
    "open the file",
]

HIGH_RISK_ATTACHMENT_PHRASES = [
    "enable content",
    "enable editing",
    "macro-enabled",
    "secure document attached",
    "review the attached html file",
    "open the attached form",
]

BENIGN_ATTACHMENT_EXTENSIONS = [
    ".pdf",
    ".docx",
    ".xlsx",
    ".pptx",
    ".txt",
    ".csv",
]

SUSPICIOUS_ATTACHMENT_EXTENSIONS = [
    ".html",
    ".htm",
    ".zip",
    ".rar",
    ".exe",
    ".iso",
    ".js",
    ".scr",
    ".bat",
    ".cmd",
    ".xlsm",
    ".docm",
]

SUSPICIOUS_BRANDS = [
    "paypal",
    "microsoft",
    "google",
    "apple",
    "amazon",
    "bank",
    "office 365",
]

GENERIC_GREETINGS = [
    "dear user", "dear customer", "dear client"
]

SUSPICIOUS_DOMAINS = [
    "mail-verification", "secure-login", "account-update"
]
