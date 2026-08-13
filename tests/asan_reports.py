"""Builders for realistic ASan report text.

The crash-analysis code in run_fuzzer.py does all of its work by reading saved ASan
reports, so most tests need report text rather than a live fuzzer binary. make_asan_log()
reproduces the parts of a real report those functions look at: the crash stack, an
allocation-site stack printed after it (which must NOT be mistaken for the crash stack),
and the trailing SUMMARY line.
"""

from collections.abc import Sequence

# Two call sites of cgltf_calc_index_bound inside cgltf_validate, taken from the real
# cgltf.h. They crash at the same place (frame #0 is identical) but are reached from
# different lines of the same calling function, which is exactly the case a signature
# built from function names alone cannot tell apart. Tests use them to pin down that
# _crash_signature compares file:line, not just names.
SPARSE_INDICES_FRAMES = [
    "cgltf_calc_index_bound cgltf_fuzz/cgltf/cgltf.h:1571:19",
    "cgltf_validate cgltf_fuzz/cgltf/cgltf.h:1632:30",
    "LLVMFuzzerTestOneInput cgltf_fuzz/harness.c:16:5",
]

PRIMITIVE_INDICES_FRAMES = [
    "cgltf_calc_index_bound cgltf_fuzz/cgltf/cgltf.h:1571:19",
    "cgltf_validate cgltf_fuzz/cgltf/cgltf.h:1719:30",
    "LLVMFuzzerTestOneInput cgltf_fuzz/harness.c:16:5",
]

# The allocation-site stack ASan prints below the crash stack for a heap overflow.
# Nothing in it should ever end up in a crash signature.
ALLOCATION_FRAMES = [
    "malloc (cgltf_fuzz/build/cgltf_fuzzer+0x12b398)",
    "cgltf_load_buffer_base64 cgltf_fuzz/cgltf/cgltf.h:1330:40",
    "cgltf_load_buffers cgltf_fuzz/cgltf/cgltf.h:1521:24",
]

DEFAULT_SUMMARY = (
    "SUMMARY: AddressSanitizer: heap-buffer-overflow "
    "cgltf_fuzz/cgltf/cgltf.h:1571:19 in cgltf_calc_index_bound"
)


def format_frames(frames: Sequence[str]) -> list[str]:
    """Render descriptions as ASan stack lines: four spaces, #N, an address, then 'in <desc>'.

    The addresses are arbitrary but plausible; real ones shift between runs under ASLR,
    which is precisely why _crash_signature strips them out.
    """
    return [f"    #{i} 0x62805a7a6c{i:02x} in {frame}" for i, frame in enumerate(frames)]


def make_asan_log(
    frames: Sequence[str] | None = None,
    alloc_frames: Sequence[str] | None = None,
    summary: str | None = DEFAULT_SUMMARY,
    banner: bool = True,
) -> str:
    """Build the text of an ASan report as reproduce_crash would have saved it.

    frames        crash-stack frame descriptions, or None for a report with no stack.
    alloc_frames  a second stack printed after the crash stack (allocation site).
    summary       the SUMMARY line, or None to omit it entirely.
    banner        whether to include libFuzzer's leading INFO/Running lines, which sit
                  above the stack and must not be parsed as frames.
    """
    lines = []
    if banner:
        lines += [
            "INFO: Running with entropic power schedule (0xFF, 100).",
            "INFO: Seed: 385490445",
            "./cgltf_fuzz/build/cgltf_fuzzer: Running 1 inputs 1 time(s) each.",
            "Running: cgltf_fuzz/crashes/crash-abc123",
            "=" * 65,
        ]

    if frames:
        lines += [
            "==1226==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x75e16f0e0160",
            "READ of size 2 at 0x75e16f0e0160 thread T0",
        ]
        lines += format_frames(frames)

    if alloc_frames:
        # The blank line here is what ends the crash stack: _crash_signature stops at the
        # first line that is not a frame once it has started collecting, so this second
        # stack must never leak into a signature.
        lines += [
            "",
            "0x75e16f0e0160 is located 239 bytes after 1-byte region",
            "allocated by thread T0 here:",
        ]
        lines += format_frames(alloc_frames)

    if summary:
        lines += ["", summary]

    lines += ["Shadow bytes around the buggy address:", "==1226==ABORTING"]
    return "\n".join(lines) + "\n"

