"""Tests for the S7CommPlus blob decompressor."""

import zlib
from itertools import accumulate

import pytest

from s7commplus import PresetStream, decompress_blob, find_and_decompress, iter_preset_streams
from s7commplus.blob_decompressor import iter_preset_headers
from s7commplus.zlib_dicts import ZLIB_DICTIONARIES, ZLIB_DICT_IDENTITIES, ZLIB_DICT_NAMES, PresetIdentity


def _preset_stream(preset: PresetIdentity, text: bytes) -> bytes:
    """Compress `text` against `preset`, prefixed with its 6-byte zlib header."""
    cobj = zlib.compressobj(wbits=-15, zdict=ZLIB_DICTIONARIES[preset.adler])
    return b"\x78\x7d" + preset.adler.to_bytes(4, "big") + cobj.compress(text) + cobj.flush()


def test_all_dictionaries_have_correct_adler32():
    for adler, data in ZLIB_DICTIONARIES.items():
        actual = zlib.adler32(data) & 0xFFFFFFFF
        assert actual == adler, f"Adler-32 mismatch for {ZLIB_DICT_NAMES.get(adler, '?')}: {actual:#x} != {adler:#x}"


def test_all_dictionaries_have_names():
    for adler in ZLIB_DICTIONARIES:
        assert adler in ZLIB_DICT_NAMES, f"Missing name for dictionary {adler:#x}"


def test_decompress_standard_blob():
    original = b"<IdentContainer><Ident Name='Tag_1' /></IdentContainer>"
    compressed = zlib.compress(original)
    result = decompress_blob(compressed)
    assert result == original.decode("utf-8")


def test_decompress_with_preset_dict():
    original = b"<IdentContainer><Ident Name='Tag_1' /></IdentContainer>"
    blob = _preset_stream(ZLIB_DICT_IDENTITIES[0xCE9B821B], original)
    assert decompress_blob(blob) == original.decode("utf-8")


def test_decompress_unknown_dict_raises():
    blob = b"\x78\x7d\xde\xad\xbe\xef" + b"\x00" * 10
    with pytest.raises(ValueError, match="Unknown zlib preset dictionary"):
        decompress_blob(blob)


def test_decompress_with_offset():
    original = b"<Test>data</Test>"
    compressed = zlib.compress(original)
    # 4-byte version prefix
    blob = b"\x00\x00\x00\x01" + compressed
    result = decompress_blob(blob, offset=4)
    assert result == original.decode("utf-8")


def test_iter_preset_headers_and_streams():
    line_comm, int_ref, ident = (ZLIB_DICT_IDENTITIES[a] for a in (0x3C55436A, 0xB0155FF8, 0xCE9B821B))
    parts = [
        b"\x00\x01",
        _preset_stream(line_comm, b"<A/>"),
        _preset_stream(line_comm, b"<A/>")[:6] + b"\xff" * 8,  # known dictionary, undecodable body
        _preset_stream(int_ref, b""),  # empty document
        b"\x78\x7d\xde\xad\xbe\xef",  # unknown dictionary
        _preset_stream(ident, b"<B/>"),
        b"\x78\x7d\xce\x9b",  # header truncated by the end of the payload
    ]
    offsets = [0, *accumulate(map(len, parts))]
    payload = b"".join(parts)

    assert list(iter_preset_headers(payload)) == [
        (offsets[1], line_comm),
        (offsets[2], line_comm),
        (offsets[3], int_ref),
        (offsets[5], ident),
    ]
    streams = list(iter_preset_streams(payload))
    assert streams == [PresetStream(line_comm, "<A/>"), PresetStream(ident, "<B/>")]
    assert [s.xml.tag for s in streams] == ["A", "B"]


def test_find_and_decompress_standard():
    original = b"<Test>hello</Test>"
    compressed = zlib.compress(original)
    # Embed in some prefix junk
    data = b"\x00\x01\x02" + compressed
    result = find_and_decompress(data)
    assert result is not None
    assert result == original.decode("utf-8")


def test_find_and_decompress_no_stream():
    result = find_and_decompress(b"\x00\x01\x02\x03\x04\x05")
    assert result is None
