"""
FileGuard honeypot module.

Contains decoy file management and access monitoring.
"""

from honeypot.decoy_manager import DecoyManager
from honeypot.monitor import HoneypotMonitor

__all__ = ["DecoyManager", "HoneypotMonitor"]
