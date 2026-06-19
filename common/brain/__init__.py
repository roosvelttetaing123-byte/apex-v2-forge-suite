"""ForgeBrain — AI Reasoning Engine for Forge Suite v5 APEX.

Uses Claude (Anthropic API) as the intelligence layer across all 4 frameworks.
Graceful degradation: if no ANTHROPIC_API_KEY, falls back to rule-based heuristics.
"""
