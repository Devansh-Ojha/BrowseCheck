"""BrowseCheck — runtime security layer for AI browser agents.

Prevention, not observation: every proposed agent action is gated by the hook
pipeline BEFORE it executes (observe -> hooks -> act).
"""

__version__ = "0.1.0"
