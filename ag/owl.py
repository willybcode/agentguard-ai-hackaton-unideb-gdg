"""OWASP Top 10 for Agentic Applications (2026) — ASI01..ASI10.

Titles transcribed from the OWASP GenAI Security Project PDF shipped in this
repo at ``information-security/materials/Lab/``.
"""

ASI = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse and Exploitation",
    "ASI03": "Identity and Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution (RCE)",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}


def label(code: str) -> str:
    return f"{code}: {ASI.get(code, 'Unknown')}"
