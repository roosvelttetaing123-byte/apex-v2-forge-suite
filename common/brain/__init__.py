"""ForgeBrain advisory reasoning for Forge Suite v5 APEX.

Model and rule output cannot approve or execute work.  Production actions must
cross :mod:`common.brain.truth_boundary` and the canonical authorization/job
services.  Without an external adapter, local rule-based advisory behavior is
retained.
"""
