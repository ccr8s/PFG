"""
FileGuard forensics module.

Contains modules for analyzing Windows forensic artifacts
including event logs, registry, timestamps, prefetch, and caches.
"""

from forensics.amcache import AmcacheParser
from forensics.bitmap_cache import BitmapCacheParser
from forensics.event_logs import EventLogAnalyzer
from forensics.prefetch import PrefetchParser
from forensics.registry import RegistryAnalyzer
from forensics.timestomp import TimestompDetector

__all__ = [
    "AmcacheParser",
    "BitmapCacheParser",
    "EventLogAnalyzer",
    "PrefetchParser",
    "RegistryAnalyzer",
    "TimestompDetector",
]
