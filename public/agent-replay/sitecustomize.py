"""Invocation-local guard for replaying only an existing upstream VCR cassette."""

from __future__ import annotations

import os

import vcr

if os.environ.get("WORKFLOW_LAB_CASSETTE_REPLAY_ONLY") != "1":
    raise RuntimeError("The Workflow Lab agent overlay is valid only for explicit cassette replay.")

_OriginalVCR = vcr.VCR


class ReplayOnlyVCR(_OriginalVCR):
    """Override the pinned upstream new-episodes default with playback-only mode."""

    def __init__(self, *args, **kwargs):
        requested_mode = kwargs.get("record_mode")
        if requested_mode != "new_episodes":
            raise RuntimeError("Pinned upstream VCR configuration changed; refusing agent replay.")
        kwargs["record_mode"] = "none"
        super().__init__(*args, **kwargs)


vcr.VCR = ReplayOnlyVCR
