use std::collections::HashMap;

pub struct LabeledSample {
    pub bytes: Vec<u8>,
    pub expected: Option<f64>,
}

pub struct FieldCandidate {
    pub name: String,
    pub ftype: String,
    pub offset: usize,
    pub length: usize,
    pub matches: usize,
    pub total: usize,
}

pub struct RuleProposal {
    pub opcode: Option<u32>,
    pub length: usize,
    pub fields: Vec<FieldCandidate>,
    pub samples: usize,
    pub labeled: usize,
}

fn decode(bytes: &[u8], ftype: &str) -> Option<f64> {
    match ftype {
        "uint8" => bytes.first().map(|b| *b as f64),
        "uint16be" => (bytes.len() >= 2).then(|| u16::from_be_bytes([bytes[0], bytes[1]]) as f64),
        "uint16le" => (bytes.len() >= 2).then(|| u16::from_le_bytes([bytes[0], bytes[1]]) as f64),
        "uint32be" => {
            (bytes.len() >= 4).then(|| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as f64)
        }
        "uint32le" => {
            (bytes.len() >= 4).then(|| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as f64)
        }
        _ => None,
    }
}

const TYPES: [(&str, usize); 5] = [
    ("uint8", 1),
    ("uint16be", 2),
    ("uint16le", 2),
    ("uint32be", 4),
    ("uint32le", 4),
];

fn infer_group(bytes_list: &[Vec<u8>], expected_list: &[f64]) -> Vec<FieldCandidate> {
    if expected_list.len() < 2 {
        return Vec::new();
    }
    let max_len = bytes_list.iter().map(|b| b.len()).max().unwrap_or(0);
    let mut out = Vec::new();
    for offset in 0..max_len {
        let mut best: Option<(&str, usize)> = None;
        for (ftype, flen) in TYPES {
            let ok = bytes_list
                .iter()
                .zip(expected_list.iter())
                .all(|(b, e)| b.len() >= offset + flen && decode(&b[offset..offset + flen], ftype) == Some(*e));
            if ok && best.map(|(_, bl)| flen > bl).unwrap_or(true) {
                best = Some((ftype, flen));
            }
        }
        if let Some((ftype, flen)) = best {
            out.push(FieldCandidate {
                name: format!("val_{offset}"),
                ftype: ftype.to_string(),
                offset,
                length: flen,
                matches: expected_list.len(),
                total: expected_list.len(),
            });
        }
    }
    out
}

pub fn infer_rules(samples: &[LabeledSample]) -> Vec<RuleProposal> {
    let mut groups: HashMap<(usize, Option<u8>), Vec<usize>> = HashMap::new();
    for (i, s) in samples.iter().enumerate() {
        groups
            .entry((s.bytes.len(), s.bytes.get(2).copied()))
            .or_default()
            .push(i);
    }
    let mut keys: Vec<(usize, Option<u8>)> = groups.keys().cloned().collect();
    keys.sort();
    let mut proposals = Vec::new();
    for (len, opcode) in keys {
        let idx = &groups[&(len, opcode)];
        let labeled: Vec<(&Vec<u8>, f64)> = idx
            .iter()
            .filter_map(|&i| samples[i].expected.map(|e| (&samples[i].bytes, e)))
            .collect();
        let expected: Vec<f64> = labeled.iter().map(|(_, e)| *e).collect();
        let raws: Vec<Vec<u8>> = labeled.iter().map(|(b, _)| (*b).clone()).collect();
        let fields = infer_group(&raws, &expected);
        proposals.push(RuleProposal {
            opcode: opcode.map(|o| o as u32),
            length: len,
            fields,
            samples: idx.len(),
            labeled: labeled.len(),
        });
    }
    proposals.sort_by(|a, b| b.samples.cmp(&a.samples));
    proposals
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(opcode: u8, extra: &[u8], value: u16) -> Vec<u8> {
        let mut v = vec![0xAA, 0x55, opcode, 0x00, extra.len() as u8 + 2];
        v.extend_from_slice(extra);
        v.extend_from_slice(&value.to_be_bytes());
        let crc = v.iter().fold(0u16, |a, b| a.wrapping_add(*b as u16));
        v.extend_from_slice(&crc.to_be_bytes());
        v
    }

    #[test]
    fn splits_by_opcode_and_finds_value() {
        let samples = vec![
            LabeledSample { bytes: frame(0x01, &[0x07], 21), expected: Some(21.0) },
            LabeledSample { bytes: frame(0x01, &[0x08], 22), expected: Some(22.0) },
            LabeledSample { bytes: frame(0x02, &[0x07], 7), expected: Some(7.0) },
            LabeledSample { bytes: frame(0x02, &[0x08], 8), expected: Some(8.0) },
            LabeledSample { bytes: "nope".as_bytes().to_vec(), expected: None },
        ];
        let rules = infer_rules(&samples);
        assert_eq!(rules.len(), 3);
        let r1 = rules.iter().find(|r| r.opcode == Some(1)).unwrap();
        assert_eq!(r1.samples, 2);
        let val = r1.fields.iter().find(|f| f.offset == 6).unwrap();
        assert_eq!(val.ftype, "uint16be");
        assert_eq!(val.matches, 2);
        let r2 = rules.iter().find(|r| r.opcode == Some(2)).unwrap();
        assert!(!r2.fields.is_empty());
    }

    #[test]
    fn varying_noise_yields_no_field() {
        let samples = vec![
            LabeledSample { bytes: vec![0xAA, 0x55, 0x01, 0xFF], expected: Some(1.0) },
            LabeledSample { bytes: vec![0xAA, 0x55, 0x01, 0x00], expected: Some(1.0) },
        ];
        let rules = infer_rules(&samples);
        assert_eq!(rules.len(), 1);
        assert!(rules[0].fields.iter().all(|f| f.offset != 3));
    }

    #[test]
    fn endianness_detected() {
        let samples = vec![
            LabeledSample { bytes: vec![0xAA, 0x55, 0x09, 0x34, 0x08], expected: Some(2100.0) },
            LabeledSample { bytes: vec![0xAA, 0x55, 0x09, 0xE8, 0x03], expected: Some(1000.0) },
        ];
        let rules = infer_rules(&samples);
        let f = rules.iter().flat_map(|r| r.fields.iter()).find(|f| f.offset == 3).unwrap();
        assert_eq!(f.ftype, "uint16le");
        assert_eq!(f.matches, 2);
    }

    #[test]
    fn empty_and_unlabeled_safe() {
        assert!(infer_rules(&[]).is_empty());
        let rules = infer_rules(&[LabeledSample { bytes: vec![1, 2], expected: None }]);
        assert_eq!(rules.len(), 1);
        assert!(rules[0].fields.is_empty());
        assert_eq!(rules[0].labeled, 0);
    }
}
