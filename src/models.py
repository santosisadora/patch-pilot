from dataclasses import dataclass
from typing import Optional

@dataclass
class Finding:
    cve_id: str
    package: str
    installed_version: str
    fixed_version: Optional[str]
    severity: str
    asset: str
    source: str = "trivy"