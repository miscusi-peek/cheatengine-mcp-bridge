from __future__ import annotations

from .models import HookDecision, HookInput
from .rescorer import rescore_hook


def decide_hook(hook: HookInput, *, backup_count: int) -> HookDecision:
    rescored = rescore_hook(hook)
    best = rescored[0] if rescored else None
    backups = rescored[1:1 + backup_count] if len(rescored) > 1 else []

    flags: list[str] = []
    if hook.error:
        flags.append(hook.error)
    if best is None:
        flags.append("no_candidates")
        summary = "No post-process decision available because no candidates were present."
    else:
        if best.final_score < 0.75:
            flags.append("low_confidence_best_candidate")
        if not best.candidate.within_range and not best.candidate.exact:
            flags.append("best_candidate_requires_manual_review")
        summary = (
            f"Selected method+{best.candidate.offset:#x} as best candidate "
            f"with final score {best.final_score:.0%}."
        )

    return HookDecision(
        hook=hook,
        best_candidate=best,
        backups=backups,
        summary=summary,
        manual_review_flags=flags,
    )
