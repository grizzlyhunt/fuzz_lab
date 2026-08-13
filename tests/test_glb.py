"""Unit tests for glb.py's binary glTF (.glb) chunk extraction.

No subprocess or built fuzzer binary is involved here: extract_glb_json only ever reads
and slices bytes, so every test builds its own minimal .glb file on disk via _glb_bytes.
"""

import pytest

from fuzz_lab import glb


def _glb_bytes(json_bytes, bin_bytes=b"", magic=b"glTF", chunk_type=b"JSON", chunk_length=None):
    """Build valid (or, via the override params, deliberately broken) .glb bytes.

    chunk_length defaults to len(json_bytes); overriding it lets a test claim a JSON
    chunk length that does not match what actually follows, without hand-computing
    the rest of the header.
    """
    if chunk_length is None:
        chunk_length = len(json_bytes)

    chunks = chunk_length.to_bytes(4, "little") + chunk_type + json_bytes
    if bin_bytes:
        chunks += len(bin_bytes).to_bytes(4, "little") + b"BIN\x00" + bin_bytes

    total_length = 12 + len(chunks)
    header = magic + (2).to_bytes(4, "little") + total_length.to_bytes(4, "little")
    return header + chunks


@pytest.fixture
def write_glb(tmp_path):
    """Return a helper writing .glb bytes to tmp_path and giving back its path."""

    def _write(name, *args, **kwargs):
        path = tmp_path / name
        path.write_bytes(_glb_bytes(*args, **kwargs))
        return str(path)

    return _write


class TestExtractGlbJson:
    def test_extracts_the_json_chunk(self, write_glb, tmp_path):
        glb_path = write_glb("crash.glb", b'{"asset":{"version":"2.0"}}')

        output_path = glb.extract_glb_json(glb_path)

        assert open(output_path, "rb").read() == b'{"asset":{"version":"2.0"}}'

    def test_writes_to_glb_path_plus_json_by_default(self, write_glb):
        glb_path = write_glb("crash.glb", b"{}")

        output_path = glb.extract_glb_json(glb_path)

        assert output_path == f"{glb_path}.json"

    def test_honours_an_explicit_output_path(self, write_glb, tmp_path):
        glb_path = write_glb("crash.glb", b"{}")
        chosen = str(tmp_path / "chunk.json")

        output_path = glb.extract_glb_json(glb_path, chosen)

        assert output_path == chosen
        assert open(chosen, "rb").read() == b"{}"

    def test_ignores_a_trailing_bin_chunk(self, write_glb):
        # The BIN chunk is where the raw (often non-UTF-8) buffer bytes live; only the
        # JSON chunk in front of it should ever end up in the extracted output.
        glb_path = write_glb("crash.glb", b'{"buffers":[{}]}', bin_bytes=b"\xff\x00\xfe\x01")

        output_path = glb.extract_glb_json(glb_path)

        assert open(output_path, "rb").read() == b'{"buffers":[{}]}'

    def test_leaves_the_original_glb_untouched(self, write_glb):
        glb_path = write_glb("crash.glb", b'{"a":1}', bin_bytes=b"\x00\x01\x02")
        before = open(glb_path, "rb").read()

        glb.extract_glb_json(glb_path)

        assert open(glb_path, "rb").read() == before

    def test_refuses_a_missing_file(self, tmp_path):
        with pytest.raises(SystemExit, match="not found"):
            glb.extract_glb_json(str(tmp_path / "no-such-file.glb"))

    def test_refuses_a_file_without_the_glb_magic(self, tmp_path):
        # e.g. a plain .gltf (starts with '{'), which has no chunk structure to extract
        # from -- it already is the JSON.
        not_a_glb = tmp_path / "plain.gltf"
        not_a_glb.write_bytes(b'{"asset":{}}')

        with pytest.raises(SystemExit, match="glTF binary header"):
            glb.extract_glb_json(str(not_a_glb))

    def test_refuses_a_file_too_short_to_hold_a_chunk_header(self, tmp_path):
        truncated = tmp_path / "truncated.glb"
        truncated.write_bytes(b"glTF" + (2).to_bytes(4, "little") + (12).to_bytes(4, "little"))

        with pytest.raises(SystemExit, match="too short"):
            glb.extract_glb_json(str(truncated))

    def test_refuses_when_the_first_chunk_is_not_json(self, write_glb):
        # Per spec the first chunk must be JSON; a file that leads with something else
        # is not a chunk layout this function understands.
        glb_path = write_glb("crash.glb", b"\x00\x01\x02\x03", chunk_type=b"BIN\x00")

        with pytest.raises(SystemExit, match="not JSON"):
            glb.extract_glb_json(glb_path)

    def test_refuses_a_json_chunk_length_running_past_the_end_of_the_file(self, write_glb):
        glb_path = write_glb("crash.glb", b"{}", chunk_length=999)

        with pytest.raises(SystemExit, match="runs past the end"):
            glb.extract_glb_json(glb_path)
