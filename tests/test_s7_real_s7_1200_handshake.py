"""Accepted V1 SessionKey handshake captured from a real S7-1200 1215C (6ES7 215-1AG40-0XB0, FW V4.2).

Reported on PR #44. Frames start at the 0x72 S7CommPlus header (no TPKT/COTP). The client
random was not recorded, so the blob cannot be regenerated; the layout, key ids and echoed
setup values can still be checked, and the emulator's own SecurityKey validation must accept it.
"""

from s7commplus.connection import _session_setup_accepted
from s7commplus.server import S7CommPlusServer

_FINGERPRINT = "01:BD426B091F08731A"

CREATE_OBJECT_RESPONSE = bytes.fromhex(
    "720100c832000004ca0000000136000287358728a100000120821f0000a38169"
    "00151330313a42443432364230393146303837333141a3822b00048280808002"
    "a3822d0015104f4d53502e52454c2e383038392e3231a3822f100214be767496"
    "ceed7704d7aa07662c3659f9303bfdcea3823200170000013a823b0004840082"
    "3c00048300823d00048480c200823e00048480c100823f00151b313b36455337"
    "203231352d31414734302d30584230203b56342e328240001506323b31303734"
    "82410003000300a20000000072010000"
)

SESSION_SETUP_REQUEST = bytes.fromhex(
    "72020180310000054200000002000003b534000003b502028e26823201001700"
    "0007088e090004008e0a0002008e0b0017000007218e220005ded0cdb0c8fc90"
    "f31a8e23000482108e24000400008e0c0017000007218e220005dbce9188e692"
    "fdc3828e2300048482018e24000400008e0d0014008134addee1feb400000001"
    "000000010000003b5746e56aa41c0001010000000000001a73081f096b42bd10"
    "01000000000000c5c20f50fb1e5fcc73504533601f64259fcd85462e72f32f3c"
    "40202b6df943cbfca27a04379fc91d7a4f4fc6f146ae4a6baf4b78fa7eb8e247"
    "67b0885bb57027a6bc2937389eef6cf18a6f7624a47519577300e26a4b2503a8"
    "986f80256d68c9805804452ba836920cf834e102c1b75cf46319f6b7fdf987a5"
    "69d62c9b9831aa87ef59e3000200170000013a823b00048400823c0004830082"
    "3d00048480c200823e00048480c100823f0015008240001506323b3130373482"
    "41000300030000000004e88969001200000000896a001300896b000400000000"
    "0000000072020000"
)

SESSION_SETUP_RESPONSE = bytes.fromhex("72020011320000054200000002340000000000000072020000")

_REQUEST_HEADER = 4 + 14  # S7CommPlus frame header + request header


def test_create_object_response_advertises_the_key_id() -> None:
    assert _FINGERPRINT.encode() in CREATE_OBJECT_RESPONSE


def test_session_setup_echoes_the_server_session_version_without_the_order_string() -> None:
    # ServerSessionVersion attributes 0x823b..0x8241 are echoed back, except that the
    # client blanks the order-number string (0x823f).
    echoed = SESSION_SETUP_REQUEST[SESSION_SETUP_REQUEST.index(bytes.fromhex("823b0004")) :]
    before, after = echoed.split(bytes.fromhex("823f0015"), 1)
    assert before in CREATE_OBJECT_RESPONSE
    assert after[1 : after.index(bytes.fromhex("8241"))] in CREATE_OBJECT_RESPONSE


def test_emulator_accepts_the_real_session_setup_request() -> None:
    server = S7CommPlusServer(public_key_fingerprint=_FINGERPRINT, session_key=bytes(24))
    request = SESSION_SETUP_REQUEST[_REQUEST_HEADER:]
    assert server._is_session_setup_write(request)
    assert server._is_valid_session_key_setup(request)


def test_session_setup_response_is_accepted() -> None:
    assert _session_setup_accepted(SESSION_SETUP_RESPONSE)
