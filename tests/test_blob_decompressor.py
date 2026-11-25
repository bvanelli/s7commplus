"""Tests for the S7CommPlus blob decompressor."""

import zlib
from importlib.resources import files
from itertools import accumulate

import pytest

from s7commplus import PresetStream, decompress_blob, find_and_decompress, iter_preset_streams
from s7commplus.blob_decompressor import compress_blob, find_preset_stream, iter_preset_headers
from s7commplus.block_interface import _INTFDESC_KINDS
from s7commplus.zlib_dicts import ZLIB_DICTIONARIES, ZLIB_DICT_IDENTITIES, ZLIB_DICT_NAMES


def test_compress_blob_round_trips_and_rejects_an_unknown_dictionary():
    text = '<Comment Path="51"><DictEntry Language="de-DE">Füllstand</DictEntry></Comment>'
    blob = compress_blob(text, 0x3C55436A)
    assert blob[:6] == bytes.fromhex("787d3c55436a")
    assert decompress_blob(blob) == text
    with pytest.raises(ValueError, match="Unknown preset dictionary 0x12345678"):
        compress_blob(text, 0x12345678)


def test_all_dictionaries_have_correct_adler32():
    for adler, data in ZLIB_DICTIONARIES.items():
        actual = zlib.adler32(data) & 0xFFFFFFFF
        assert actual == adler, f"Adler-32 mismatch for {ZLIB_DICT_NAMES.get(adler, '?')}: {actual:#x} != {adler:#x}"


def test_all_dictionaries_have_names():
    for adler in ZLIB_DICTIONARIES:
        assert adler in ZLIB_DICT_NAMES, f"Missing name for dictionary {adler:#x}"


@pytest.mark.parametrize("adler", sorted(ZLIB_DICT_IDENTITIES), ids=lambda a: f"{a:08x}")
def test_dictionary_identity_round_trips_to_its_file(adler: int):
    preset = ZLIB_DICT_IDENTITIES[adler]

    # Keyed by its own Adler-32, which also fits the 4-byte zlib DICTID.
    assert preset.adler == adler
    assert 0 <= preset.adler <= 0xFFFFFFFF
    assert 0 <= preset.version <= 0xFFFFFFFF
    # Underscores became spaces, and nothing was left at the edges by the split.
    assert preset.kind and preset.kind == preset.kind.strip() and "_" not in preset.kind

    # Rebuilding the name from the parsed fields must land on the shipped file.
    name = f"{preset.adler:08x}_{preset.kind.replace(' ', '_')}_{preset.version:08x}.xml"
    assert files("s7commplus.zlib_dicts").joinpath(name).is_file()
    # The display name is the same identity in its older flat form.
    assert ZLIB_DICT_NAMES[adler] == f"{preset.kind} {preset.version:08x}"


def test_decompress_standard_blob():
    original = b"<IdentContainer><Ident Name='Tag_1' /></IdentContainer>"
    compressed = zlib.compress(original)
    result = decompress_blob(compressed)
    assert result == original.decode("utf-8")


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
        compress_blob("<A/>", line_comm.adler),
        compress_blob("<A/>", line_comm.adler)[:6] + b"\xff" * 8,  # known dictionary, undecodable body
        compress_blob("", int_ref.adler),  # empty document
        b"\x78\x7d\xde\xad\xbe\xef",  # unknown dictionary
        compress_blob("<B/>", ident.adler),
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


@pytest.mark.parametrize("adlers", [(0x79B2BDA3, 0x3C55436A), (0x3C55436A, 0x79B2BDA3)], ids=["old-first", "new-first"])
def test_iter_preset_streams_keeps_payload_order_across_versions(adlers: tuple[int, int]):
    # LineComm 0x90000001 and 0x98000001 in both orders: the output follows the payload,
    # not the Adler-32 order of ZLIB_DICT_IDENTITIES.
    first, second = (ZLIB_DICT_IDENTITIES[a] for a in adlers)
    payload = compress_blob("<First/>", first.adler) + compress_blob("<Second/>", second.adler)

    assert list(iter_preset_streams(payload)) == [PresetStream(first, "<First/>"), PresetStream(second, "<Second/>")]


def test_iter_preset_streams_skips_header_inside_compressed_data():
    # Level 0 stores the bytes verbatim, so a real preset header shows up inside a standard stream.
    ident = ZLIB_DICT_IDENTITIES[0xCE9B821B]
    payload = zlib.compress(b"<Outer>" + compress_blob("", ident.adler)[:6] + b"<B/></Outer>", 0)

    assert [preset for _, preset in iter_preset_headers(payload)] == [ident]
    assert list(iter_preset_streams(payload)) == []


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


def test_find_preset_stream_matches_kind_across_versions():
    # LineComm 0x90000001 then 0x98000001: the first stream of the kind wins, whatever its version.
    # Only headers are read, so the streams need no body.
    payload = bytes.fromhex("787d 79b2bda3 787d 3c55436a")
    assert find_preset_stream(payload, ("LineComm",)) == 0
    assert find_preset_stream(payload, ("IntfDesc",)) is None


def test_find_preset_stream_accepts_a_single_kind():
    # "IntfDesc" is a substring of "DebugInfo IntfDesc", but a single kind must match whole
    payload = bytes.fromhex("787d 79b2bda3 787d 66052b13")
    assert find_preset_stream(payload, "LineComm") == 0
    assert find_preset_stream(payload, "IntfDesc") is None
    assert find_preset_stream(payload, "Comm") is None


def test_find_preset_stream_prefers_debuginfo_intfdesc():
    # IntfDesc then DebugInfo IntfDesc: the optimized interface wins although it comes second.
    payload = bytes.fromhex("787d 4b8416f0 787d 66052b13")
    assert find_preset_stream(payload, _INTFDESC_KINDS) == 6
    assert find_preset_stream(payload[6:] + payload[:6], _INTFDESC_KINDS) == 0
