from client.realtime import parse_realtime_event


def test_parse_realtime_event_accepts_message_event():
    event = parse_realtime_event('{"type":"message","sender":"alice","packet":{"ciphertext_b64":"abc"}}')

    assert event == {"type": "message", "sender": "alice", "packet": {"ciphertext_b64": "abc"}}


def test_parse_realtime_event_rejects_malformed_payloads():
    assert parse_realtime_event("not-json") is None
    assert parse_realtime_event('{"sender":"alice"}') is None
    assert parse_realtime_event('["message"]') is None
