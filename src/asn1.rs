use ramp::int::Int;
use crate::ops::IntOpsExt;

#[derive(Debug)]
pub enum ASN1Error {
    NotEnoughBytes,
    WrongType,
    InvalidLength,
}

fn encode_asn1_length(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else {
        let mut asn1 = Vec::new();
        let int_bytes = Int::from(len).to_bytes();
        asn1.push(0x80 | int_bytes.len() as u8);
        asn1.extend_from_slice(&int_bytes);

        asn1
    }
}

pub fn encode_asn1_octet_str(data: &[u8]) -> Vec<u8> {
    let mut asn1 = Vec::new();
    asn1.push(0x04); // Primitive OCTET STRING
    asn1.extend_from_slice(&encode_asn1_length(data.len()));    
    asn1.extend_from_slice(&data);

    asn1
}

pub fn encode_asn1_oid(tree: &[usize]) -> Vec<u8> {
    let mut asn1 = Vec::new();
    asn1.push(0x06u8);

    let mut oid_bytes = Vec::new();
    for entry in tree.iter() {
        let mut entry_bytes = Vec::new();
        let mut remainder = *entry;

        // Generate encoding of entry in reverse order
        while remainder > 0 {
            let mut current_byte = remainder % 128;

            if entry_bytes.len() > 0 {
                current_byte |= 0x80;
            }

            entry_bytes.push(current_byte as u8);

            remainder /= 128;
        }

        oid_bytes.extend(entry_bytes.iter().rev());
    }

    asn1.extend_from_slice(&encode_asn1_length(oid_bytes.len()));
    asn1.extend_from_slice(&oid_bytes);

    asn1
}

pub fn encode_asn1_integer(val: &Int) -> Vec<u8> {
    let int_bytes = val.to_bytes();
    let mut asn1 = Vec::new();
    asn1.push(0x02); // Primitive INTEGER
    asn1.extend_from_slice(&encode_asn1_length(int_bytes.len()));
    asn1.extend_from_slice(&int_bytes);

    asn1
}

pub fn encode_asn1_sequence(items: &[Vec<u8>]) -> Vec<u8> {
    let mut asn1 = Vec::new();
    asn1.push(0x30); // Constructed SEQUENCE

    let total_len = items.iter().fold(0, |a, x| a + x.len());

    asn1.extend_from_slice(&encode_asn1_length(total_len));

    for item in items.iter() {
        asn1.extend_from_slice(&item);
    }

    asn1
}

fn decode_asn1_length(data: &[u8]) -> Result<(&[u8], usize), ASN1Error> {
    let len_byte = match data.get(0) {
        Some(v) => *v,
        None => return Err(ASN1Error::NotEnoughBytes),
    };

    let is_multibyte_len = len_byte & 0x80 != 0;
    let len = len_byte as usize & 0x7f;

    if is_multibyte_len {
        // Make sure it fits in a usize
        if len > std::mem::size_of::<usize>() {
            return Err(ASN1Error::InvalidLength);
        }

        // remaining data too short
        if data.len() < len + 1 {
            return Err(ASN1Error::NotEnoughBytes);
        }

        let mut len_decoded = 0; 
        for b in data.iter().take(len) {
            len_decoded <<= 8;
            len_decoded |= *b as usize;
        }

        Ok((&data[1+len..], len_decoded))
    } else {
        Ok((&data[1..], len))
    }
}

fn decode_asn1_verify_type_get_len(expected_type: u8, data: &[u8]) -> Result<(&[u8], usize), ASN1Error> {
    let type_byte = match data.get(0) {
        Some(v) => *v,
        None => return Err(ASN1Error::NotEnoughBytes),
    };

    if type_byte != expected_type {
        return Err(ASN1Error::WrongType);
    }

    decode_asn1_length(&data[1..])   
}

fn decode_asn1_oid_item(data: &[u8]) -> Result<(&[u8], usize), ASN1Error> {
    let mut len = 0;
    let mut idx = 0;
    while let Some(b) = data.get(idx)  {
        if b & 0x80 != 0 {
            len += *b as usize & 0x7f;
            len <<= 7;
        } else {
            len += *b as usize;
            return Ok((&data[idx+1..], len));
        }

        idx += 1;
    }

    Err(ASN1Error::NotEnoughBytes)
}

pub fn decode_asn1_octet_str(data: &[u8]) -> Result<(&[u8], &[u8]), ASN1Error> {
    let (next, len) = decode_asn1_verify_type_get_len(0x04, data)?;

    if next.len() < len {
        Err(ASN1Error::NotEnoughBytes)
    } else {
        Ok((&next[len..], &next[..len]))
    }
}

pub fn decode_asn1_oid(data: &[u8]) -> Result<(&[u8], Vec<usize>), ASN1Error> {
    let (next, len) = decode_asn1_verify_type_get_len(0x06, data)?;

    if next.len() < len {
        Err(ASN1Error::NotEnoughBytes)
    } else {
        let mut oid_data = &next[..len];
        let mut oids = Vec::new();

        while oid_data.len() > 0 {
            let (next, oid) = decode_asn1_oid_item(&oid_data)?;

            oid_data = next;
            oids.push(oid);
        }

        Ok((&next[len..], oids))
    }

}

pub fn decode_asn1_integer(data: &[u8]) -> Result<(&[u8], Int), ASN1Error> {
    let (next, len) = decode_asn1_verify_type_get_len(0x02, data)?;

    if next.len() < len {
        Err(ASN1Error::NotEnoughBytes)
    } else {
        Ok((&next[len..], Int::from_bytes(&next[..len])))
    }
}

pub fn decode_asn1_sequence(data: &[u8]) -> Result<(&[u8], &[u8]), ASN1Error> {
    let (next, len) = decode_asn1_verify_type_get_len(0x30, data)?;

    if next.len() < len {
        Err(ASN1Error::NotEnoughBytes)
    } else {
        Ok((&next[len..], &next[..len]))
    }
}

#[cfg(test)]
mod tests {
    use ramp::int::Int;
    use hex;
    use super::*;

    #[test]
    fn test_encode_seq() {
        let small_int = Int::from(0x12345789);
        let big_int = Int::from(2).pow(1024);

        let seq_enc = encode_asn1_sequence(
            &[encode_asn1_integer(&small_int),
            encode_asn1_integer(&big_int)]);

        println!("Seq = {}", hex::encode(&seq_enc));
    }
}
