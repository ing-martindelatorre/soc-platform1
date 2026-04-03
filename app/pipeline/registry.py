from app.modules.sentinel.service import SentinelPipeline
from app.modules.snyk.service import SnykPipeline
from app.modules.nmap.service import NmapPipeline
from app.modules.fortinet.service import FortinetPipeline


MODULES = {
    "sentinel": SentinelPipeline(),
    "snyk": SnykPipeline(),
    "nmap": NmapPipeline(),
    "fortinet": FortinetPipeline(),
}