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
    in_kev: bool = False
    epss: float = 0.0
    epss_percentile: float = 0.0
    priority: str = "P3"
    reason: str = ""