use protocol_lab_core::interpreter::{apply_rule, frame_stream, FieldType, FramingRule, InterpretationRule};

fn rule(offset: usize, field_type: FieldType) -> InterpretationRule {
    InterpretationRule {
        name: "test".to_string(),
        offset,
        field_type,
    }
}

#[test]
fn applies_rule_at_offset() {
    let data = [0xAA, 0xBB, 0x12, 0x34];
    let parsed = apply_rule(&data, &rule(2, FieldType::U16Big)).expect("правило должно примениться");
    assert_eq!(parsed["value"], 0x1234);
    assert_eq!(parsed["offset"], 2);
    assert_eq!(parsed["length"], 2);
}

#[test]
fn missing_bytes_at_offset_returns_none() {
    let data = [0xAA, 0xBB, 0x12];
    assert!(apply_rule(&data, &rule(2, FieldType::U16Big)).is_none());
}

#[test]
fn offset_beyond_message_returns_none() {
    let data = [0xAA, 0xBB];
    assert!(apply_rule(&data, &rule(5, FieldType::U8)).is_none());
}

#[test]
fn little_endian_at_offset() {
    let data = [0x00, 0x01, 0x34, 0x12];
    let parsed = apply_rule(&data, &rule(2, FieldType::U16Little)).expect("правило должно примениться");
    assert_eq!(parsed["value"], 0x1234);
}

#[test]
fn fixed_size_framing_emits_incomplete_tail() {
    let data = [0u8; 10];
    let messages = frame_stream(&data, &FramingRule::FixedSize(4));

    assert_eq!(messages.len(), 3);
    assert_eq!(messages[0].stream_offset, 0);
    assert_eq!(messages[1].stream_offset, 4);
    assert!(!messages[0].incomplete && !messages[1].incomplete);
    assert_eq!(messages[2].stream_offset, 8);
    assert_eq!(messages[2].payload.len(), 2);
    assert!(messages[2].incomplete);
}

#[test]
fn fixed_size_framing_without_tail_is_complete() {
    let data = [0u8; 8];
    let messages = frame_stream(&data, &FramingRule::FixedSize(4));
    assert_eq!(messages.len(), 2);
    assert!(messages.iter().all(|m| !m.incomplete));
}

#[test]
fn fixed_size_zero_rule_terminates() {
    let data = [1u8, 2, 3];
    let messages = frame_stream(&data, &FramingRule::FixedSize(0));
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].stream_offset, 0);
    assert_eq!(messages[0].payload, data.to_vec());
    assert!(messages[0].incomplete);
}

#[test]
fn length_prefixed_one_byte_frames_and_marks_tail() {
    let data = [3, 0xAA, 0xBB, 0xCC, 2, 0xDD, 0xEE, 7, 0x11];
    let messages = frame_stream(&data, &FramingRule::LengthPrefixed);

    assert_eq!(messages.len(), 3);
    assert_eq!(messages[0].stream_offset, 0);
    assert_eq!(messages[0].payload, vec![0xAA, 0xBB, 0xCC]);
    assert_eq!(messages[1].stream_offset, 4);
    assert_eq!(messages[1].payload, vec![0xDD, 0xEE]);
    assert!(messages[0].incomplete == false && messages[1].incomplete == false);
    assert_eq!(messages[2].stream_offset, 7);
    assert_eq!(messages[2].payload, vec![7, 0x11]);
    assert!(messages[2].incomplete);
}

#[test]
fn length_prefixed_u16_frames_messages() {
    let data = [0x00, 0x03, 1, 2, 3, 0x00, 0x02, 4, 5];
    let messages = frame_stream(&data, &FramingRule::LengthPrefixedU16Big);

    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].stream_offset, 0);
    assert_eq!(messages[0].payload, vec![1, 2, 3]);
    assert_eq!(messages[1].stream_offset, 5);
    assert_eq!(messages[1].payload, vec![4, 5]);
    assert!(messages.iter().all(|m| !m.incomplete));
}

#[test]
fn length_prefixed_u16_marks_truncated_body() {
    let data = [0x00, 0x05, 1, 2];
    let messages = frame_stream(&data, &FramingRule::LengthPrefixedU16Big);

    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].stream_offset, 0);
    assert_eq!(messages[0].payload, data.to_vec());
    assert!(messages[0].incomplete);
}

#[test]
fn clean_stream_framing_has_no_incomplete_messages() {
    let data = [1, 0xAA, 1, 0xBB, 1, 0xCC];
    let messages = frame_stream(&data, &FramingRule::LengthPrefixed);
    assert_eq!(messages.len(), 3);
    assert!(messages.iter().all(|m| !m.incomplete));
}
