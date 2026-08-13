"""Byte-level helpers for the binary glTF (.glb) container format.

A .glb starts with a 12-byte header (magic "glTF", version, total file length in
bytes), followed by one or more chunks, each with its own 4-byte length + 4-byte type
sub-header. The first chunk is always JSON; a fuzzer-found .glb crash typically has a
second "BIN" chunk right after it holding the raw buffer bytes referenced by
bufferViews. See the glTF 2.0 spec's "Binary glTF Layout" section for the full format.
"""

import os

__all__ = ["extract_glb_json"]

_HEADER_SIZE = 12
_CHUNK_HEADER_SIZE = 8


def extract_glb_json(glb_path, output_path=None):
    """Pull the JSON chunk out of a .glb file and write it to its own file.

    Lets a fuzzer-found .glb crash be hand-edited safely: plain glTF JSON is valid
    UTF-8, so unlike the .glb as a whole (whose later BIN chunk, if any, is raw binary,
    not text), it survives a text editor's decode/re-encode round trip without silent
    corruption. output_path defaults to glb_path + '.json'; everything from the BIN
    chunk onward, if present, is left on disk untouched.
    """
    if not os.path.isfile(glb_path):
        raise SystemExit(f"{glb_path} not found.")
    if output_path is None:
        output_path = f"{glb_path}.json"

    with open(glb_path, "rb") as glb_file:
        data = glb_file.read()

    if data[:4] != b"glTF":
        raise SystemExit(f"{glb_path} does not start with a glTF binary header.")
    if len(data) < _HEADER_SIZE + _CHUNK_HEADER_SIZE:
        raise SystemExit(f"{glb_path} is too short to hold a chunk header.")

    chunk_length = int.from_bytes(data[12:16], "little")
    chunk_type = data[16:20]
    if chunk_type != b"JSON":
        raise SystemExit(f"{glb_path}'s first chunk is {chunk_type!r}, not JSON.")

    chunk_start = _HEADER_SIZE + _CHUNK_HEADER_SIZE
    chunk_end = chunk_start + chunk_length
    if chunk_end > len(data):
        raise SystemExit(
            f"{glb_path}'s JSON chunk claims {chunk_length} bytes, which runs past the end of the file."
        )

    with open(output_path, "wb") as out_file:
        out_file.write(data[chunk_start:chunk_end])

    print(f"JSON chunk ({chunk_length} bytes) written to {output_path}.")
    return output_path
