"""Unit tests for run_fuzzer.py's ASan-report analysis helpers.

These functions decide whether two crashes are "the same bug", which is what
dedupe_crashes acts on when it deletes files -- so they get the most scrutiny in this
suite. Everything here works off report text on disk; no subprocess is involved.
"""

import os
from unittest import mock

import run_fuzzer
from asan_reports import (
    ALLOCATION_FRAMES,
    DEFAULT_SUMMARY,
    PRIMITIVE_INDICES_FRAMES,
    SPARSE_INDICES_FRAMES,
)


class TestSanitizerEnv:
    def test_sets_the_dedup_token_length_libfuzzer_reads(self):
        assert run_fuzzer._sanitizer_env()["ASAN_OPTIONS"] == "dedup_token_length=3"

    def test_asks_ubsan_to_print_a_stack_trace(self):
        # Without this, a UBSan-only report (e.g. a misaligned load) has no frames for
        # _crash_signature to read, so it can never be confirmed to be the same bug as
        # anything else.
        assert run_fuzzer._sanitizer_env()["UBSAN_OPTIONS"] == "print_stacktrace=1"

    def test_carries_the_ambient_environment_along(self):
        # minimize_crash runs a real compiled binary, which still needs PATH and friends.
        with mock.patch.dict(os.environ, {"PROJECT_MARKER": "present"}):
            assert run_fuzzer._sanitizer_env()["PROJECT_MARKER"] == "present"

    def test_does_not_mutate_the_ambient_environment(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            run_fuzzer._sanitizer_env()
            assert "ASAN_OPTIONS" not in os.environ
            assert "UBSAN_OPTIONS" not in os.environ


class TestSummaryLine:
    def test_extracts_the_summary_line(self, write_log):
        log = write_log("crash.log")
        assert run_fuzzer._summary_line(log) == DEFAULT_SUMMARY

    def test_returns_none_when_the_report_has_no_summary(self, write_log):
        # A timeout or OOM report, or a run that never crashed at all.
        log = write_log("clean.log", frames=SPARSE_INDICES_FRAMES, summary=None)
        assert run_fuzzer._summary_line(log) is None

    def test_ignores_summary_like_text_that_is_not_at_line_start(self, write_log):
        # The regex is anchored with re.MULTILINE, so an indented mention inside another
        # line must not be picked up as the report's own verdict.
        log = write_log("crash.log", summary="  mentions SUMMARY: but is indented")
        assert run_fuzzer._summary_line(log) is None


class TestCrashSignature:
    def test_returns_the_first_frames_of_the_crash_stack(self, write_log):
        log = write_log("crash.log", frames=SPARSE_INDICES_FRAMES)
        assert run_fuzzer._crash_signature(log) == tuple(SPARSE_INDICES_FRAMES)

    def test_strips_the_frame_number_and_address(self, write_log):
        # Addresses move between runs under ASLR; keeping them would make every report
        # look like a different bug.
        log = write_log("crash.log", frames=SPARSE_INDICES_FRAMES)
        signature = run_fuzzer._crash_signature(log)

        # Asserted rather than indexed straight away: the signature is Optional, and an
        # unexpected None should fail here instead of as a TypeError further down.
        assert signature is not None
        assert not signature[0].startswith("#")
        assert "0x" not in signature[0]

    def test_skips_the_libfuzzer_banner_above_the_stack(self, write_log):
        log = write_log("crash.log", frames=SPARSE_INDICES_FRAMES, banner=True)
        signature = run_fuzzer._crash_signature(log)

        assert signature is not None
        assert signature[0].startswith("cgltf_calc_index_bound")

    def test_stops_before_the_allocation_stack_printed_after_the_crash_stack(self, write_log):
        # An ASan heap-overflow report prints a second stack for the allocation site.
        # Letting it bleed into the signature would make unrelated crashes that happen to
        # share an allocation path look identical.
        log = write_log("crash.log", frames=SPARSE_INDICES_FRAMES[:2], alloc_frames=ALLOCATION_FRAMES)
        signature = run_fuzzer._crash_signature(log)

        assert signature == tuple(SPARSE_INDICES_FRAMES[:2])
        assert signature is not None
        assert not any("malloc" in frame for frame in signature)

    def test_honours_a_custom_depth(self, write_log):
        log = write_log("crash.log", frames=SPARSE_INDICES_FRAMES)
        assert run_fuzzer._crash_signature(log, depth=2) == tuple(SPARSE_INDICES_FRAMES[:2])

    def test_returns_a_short_stack_as_is_when_it_has_fewer_frames_than_depth(self, write_log):
        log = write_log("crash.log", frames=SPARSE_INDICES_FRAMES[:1])
        assert run_fuzzer._crash_signature(log, depth=3) == tuple(SPARSE_INDICES_FRAMES[:1])

    def test_returns_none_when_the_report_has_no_stack(self, write_log):
        log = write_log("nostack.log", frames=None)
        assert run_fuzzer._crash_signature(log) is None


class TestSameBug:
    def test_identical_reports_are_the_same_bug(self, write_log):
        first = write_log("a.log", frames=SPARSE_INDICES_FRAMES)
        second = write_log("b.log", frames=SPARSE_INDICES_FRAMES)
        assert run_fuzzer._same_bug(first, second) is True

    def test_same_crash_site_reached_from_a_different_call_site_is_a_different_bug(self, write_log):
        # The regression this whole signature scheme exists for: cgltf_validate calls
        # cgltf_calc_index_bound from cgltf.h:1632 (sparse indices) and cgltf.h:1719
        # (primitive indices). Both crash at cgltf.h:1571, so they share a SUMMARY line
        # and share ASan's function-name-only DEDUP_TOKEN -- but they are plausibly two
        # separate missing checks, and dedupe_crashes must not delete one as a copy of
        # the other.
        sparse = write_log("sparse.log", frames=SPARSE_INDICES_FRAMES)
        primitive = write_log("primitive.log", frames=PRIMITIVE_INDICES_FRAMES)

        assert run_fuzzer._summary_line(sparse) == run_fuzzer._summary_line(primitive)
        assert run_fuzzer._same_bug(sparse, primitive) is False

    def test_differing_deeper_frames_are_a_different_bug(self, write_log):
        other_caller = SPARSE_INDICES_FRAMES[:2] + ["cgltf_parse_file cgltf_fuzz/cgltf.h:2000:1"]
        first = write_log("a.log", frames=SPARSE_INDICES_FRAMES)
        second = write_log("b.log", frames=other_caller)
        assert run_fuzzer._same_bug(first, second) is False

    def test_an_unparseable_report_is_never_the_same_bug(self, write_log):
        # Two reports we cannot read are not evidence of anything, least of all of being
        # duplicates -- returning True here would delete files on no information at all.
        first = write_log("a.log", frames=None)
        second = write_log("b.log", frames=None)
        assert run_fuzzer._same_bug(first, second) is False

    def test_a_parseable_report_never_matches_an_unparseable_one(self, write_log):
        first = write_log("a.log", frames=SPARSE_INDICES_FRAMES)
        second = write_log("b.log", frames=None)
        assert run_fuzzer._same_bug(first, second) is False

