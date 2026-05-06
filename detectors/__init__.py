"""
FileGuard detectors module.

Contains detection modules for YARA rules, hashes, entropy,
patterns, PE file analysis, ADS scanning, packer detection,
and Sigma rule engine.
"""

from detectors.ads_scanner import ADSScanner
from detectors.entropy_detector import EntropyDetector
from detectors.hash_detector import HashDetector
from detectors.packer_detector import PackerDetector
from detectors.pattern_detector import PatternDetector
from detectors.pe_analyzer import PEAnalyzer
from detectors.sigma_detector import SigmaEngine
from detectors.yara_detector import YaraDetector

__all__ = [
    "ADSScanner",
    "EntropyDetector",
    "HashDetector",
    "PackerDetector",
    "PatternDetector",
    "PEAnalyzer",
    "SigmaEngine",
    "YaraDetector",
]
