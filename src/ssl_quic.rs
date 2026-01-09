use crate::config::Config;
use crate::errors::ParseErrorType::Invalid_TLS_Packet;
use crate::errors::Parse_error;
use crate::packet_info::{Packet_Info_List, Packet_info, Transport_Protocol};
use crate::ssl_helper::{ssl_parse_slice, ssl_parse_slice_mut, ssl_read_u16, ssl_read_u24, ssl_read_u32, ssl_read_u8};
use crate::statistics::Statistics;
use crate::TLS_Protocol;
use aes::Aes128;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{AeadInPlace, Aes128Gcm};
use chrono::{DateTime, Utc};
use cipher::{BlockEncrypt, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;
use std::error::Error;
use std::net::IpAddr;
use tracing::debug;

const QUIC_V1_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

fn hkdf_expand_label(secret: &[u8], label: &str, length: usize) -> Result<Vec<u8>, Parse_error> {
    let hk = Hkdf::<Sha256>::from_prk(secret)
        .map_err(|_| Parse_error::new(Invalid_TLS_Packet, "Invalid PRK length for SHA256"))?;
    // 1. Build the "tls13 " prefixed label
    let full_label = format!("tls13 {label}");

    // 2. Construct the 'info' byte sequence:
    // [2 bytes: length] [1 byte: label_length] [label] [1 byte: 0x00 (context length)]
    let mut info = Vec::new();
    info.extend_from_slice(&(length as u16).to_be_bytes()); // Output length (big-endian)
    info.push(full_label.len() as u8); // Label length
    info.extend_from_slice(full_label.as_bytes()); // The label itself
    info.push(0); // Context length (always 0)

    let mut okm = vec![0u8; length];
    hk.expand(&info, &mut okm)
        .map_err(|_| Parse_error::new(Invalid_TLS_Packet, "HKDF expansion failed"))?;
    Ok(okm)
}

#[must_use]
pub fn calculate_initial_secret(salt: &[u8], cid: &[u8]) -> Vec<u8> {
    // HKDF-Extract returns (PseudoRandomKey, HkdfObj)
    // The PseudoRandomKey is our initial_secret.
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), cid);

    // Convert the output to a Vec for easy handling
    prk.to_vec()
}
fn derive_initial_secret(dcid: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let initial_secret = calculate_initial_secret(&QUIC_V1_SALT, dcid);
    let client_secret = hkdf_expand_label(&initial_secret, "client in", 32)?;
    let server_secret = hkdf_expand_label(&initial_secret, "server in", 32)?;

    Ok((client_secret, server_secret))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_quic_initial_secret_derivation() {
        // This is the CID used in the RFC test vector
        let cid: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

        // 2. Expected output provided by you (and RFC 9001)
        let expected_hex = "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44";

        // 3. Calculate the secret
        let secret = calculate_initial_secret(&QUIC_V1_SALT, &cid);

        // 4. Verification
        let result_hex = hex::encode(secret);
        assert_eq!(result_hex, expected_hex);
        println!("Success! Calculated Secret: {}", result_hex);
    }
    #[test]
    fn test_rfc9001_appendix_a_initial_secrets() {
        // Initial secret test vectors from RFC 9001, Appendix A.1
        let dcid = hex::decode("8394c8f03e515708").unwrap();

        let (client_secret, server_secret) = derive_initial_secret(&dcid).unwrap();

        // Expected Initial Secret (extracted intermediate value from RFC)
        // initial_secret = HKDF-Extract(salt, dcid)
        // RFC value: 7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44

        // Expected Client Initial Secret
        // RFC value: c00cf151ca5be075ed0ebfb5c803ad3f5196a0bb2ed13875691459a499801295
        let expected_client = "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea";
        assert_eq!(hex::encode(client_secret), expected_client);

        // Expected Server Initial Secret
        // RFC value: d0ed82005c7448d5d1451000b0f75143003b57084531818d360814917a126742
        let expected_server = "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b";
        assert_eq!(hex::encode(server_secret), expected_server);
    }

    #[test]
    fn test_rfc9001_appendix_a2_client_initial_keys() {
        // RFC 9001 Appendix A.2 - Client Initial packet protection keys
        let client_secret =
            hex::decode("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
                .unwrap();
        let keys = derive_packet_keys(&client_secret).unwrap();

        // Expected values from RFC 9001 A.2
        assert_eq!(hex::encode(keys.key), "1f369613dd76d5467730efcbe3b1a22d");
        assert_eq!(hex::encode(keys.iv), "fa044b2f42a3fd3b46fb255c");
        assert_eq!(hex::encode(keys.hp), "9f50449e04a0e810283a1e9933adedd2");
    }

    #[test]
    fn test_rfc9001_appendix_a2_server_initial_keys() {
        // RFC 9001 Appendix A.2 - Server Initial packet protection keys
        let server_secret =
            hex::decode("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
                .unwrap();
        let keys = derive_packet_keys(&server_secret).unwrap();

        // Expected values from RFC 9001 A.2
        assert_eq!(hex::encode(keys.key), "cf3a5331653c364c88f0f379b6067e37");
        assert_eq!(hex::encode(keys.iv), "0ac1493ca1905853b0bba03e");
        assert_eq!(hex::encode(keys.hp), "c206b8d9b9f0f37644430b490eeaa314");
    }
}
struct PacketKeys {
    hp: [u8; 16],
    key: [u8; 16],
    iv: [u8; 12],
}

fn derive_packet_keys(secret: &[u8]) -> Result<PacketKeys, Parse_error> {
    Ok(PacketKeys {
        hp: hkdf_expand_label(secret, "quic hp", 16)?
            .try_into()
            .map_err(|_| Parse_error::new(Invalid_TLS_Packet, "QUIC HP key size mismatch"))?,
        key: hkdf_expand_label(secret, "quic key", 16)?
            .try_into()
            .map_err(|_| Parse_error::new(Invalid_TLS_Packet, "QUCI key size mismatch"))?,
        iv: hkdf_expand_label(secret, "quic iv", 12)?
            .try_into()
            .map_err(|_| Parse_error::new(Invalid_TLS_Packet, "QUIC IV size mismatch"))?,
    })
}

/// Removes QUIC header protection in-place
///
/// `packet` = full QUIC packet buffer
/// `pn_offset` = offset of packet number field
/// `hp_key` = header protection key (16 bytes for AES-128)
pub fn remove_header_protection(
    packet: &mut [u8],
    pn_offset: usize,
    hp_key: &[u8; 16],
) -> Result<usize, Box<dyn Error>> {
    // Sample is always 16 bytes starting 4 bytes after PN start
    let sample_offset = pn_offset + 4;
    let sample = ssl_parse_slice(packet, sample_offset..sample_offset + 16)?;

    // Encrypt sample with AES-ECB
    let cipher = Aes128::new(GenericArray::from_slice(hp_key));
    let mut block = GenericArray::clone_from_slice(sample);
    cipher.encrypt_block(&mut block);

    let mask = block.as_slice();

    // Long header: mask lower 4 bits of the first byte
    packet[0] ^= mask[0] & 0x0f;

    // Packet number length is encoded in low 2 bits
    let pn_len = (packet[0] & 0x03) as usize + 1;
    if packet.len() < pn_offset + pn_len {
        return Err(Parse_error::new(
            Invalid_TLS_Packet,
            &format!("Packet too short {:x}", packet.len()),
        )
        .into());
    }

    // Unmask packet number bytes
    for i in 0..pn_len {
        packet[pn_offset + i] ^= mask[1 + i];
    }

    Ok(pn_len)
}

fn parse_varint(buf: &[u8], offset: usize) -> Result<(u64, usize), Parse_error> {
    let remaining = buf.get(offset..).ok_or_else(|| {
        Parse_error::new(
            Invalid_TLS_Packet,
            &format!(
                "Offset {} out of bounds for buffer length {offset}",
                buf.len()
            ),
        )
    })?;

    if remaining.is_empty() {
        return Err(Parse_error::new(
            Invalid_TLS_Packet,
            &format!("Empty buffer at offset {offset}"),
        ));
    }

    let first = remaining[0];
    let len = match first >> 6 {
        0b00 => 1,
        0b01 => 2,
        0b10 => 4,
        0b11 => 8,
        _ => unreachable!(),
    };

    if remaining.len() < len {
        return Err(Parse_error::new(
            Invalid_TLS_Packet,
            &format!(
                "Packet too short: expected {len} bytes, got {}",
                remaining.len()
            ),
        ));
    }

    let mut value = u64::from(first & 0x3f);
    for i in 1..len {
        value = (value << 8) | u64::from(remaining[i]);
    }

    Ok((value, len))
}
fn decrypt_quic_payload(
    aead_key: &[u8],
    iv: &[u8],
    packet_number: u64,
    ciphertext: &mut [u8],
    aad: &[u8],
) -> Result<usize, Box<dyn Error>> {
    if aead_key.len() != 16 || iv.len() != 12 {
        return Err(Parse_error::new(
            Invalid_TLS_Packet,
            &format!(
                "Mismatch IV and AAD length {} {} ",
                aead_key.len(),
                iv.len()
            ),
        )
        .into());
    }

    // debug!("payload: {:x?} {}", &ciphertext[0..4], ciphertext.len());
    let cipher = Aes128Gcm::new(GenericArray::from_slice(aead_key));

    // compute nonce = IV ⊕ packet_number
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(iv);
    let pn_bytes = packet_number.to_be_bytes(); // 8 bytes
                                                // XOR last 8 bytes of IV with packet number
    for i in 0..8 {
        nonce_bytes[4 + i] ^= pn_bytes[i];
    }
    let nonce = GenericArray::from_slice(&nonce_bytes);
    let tag_pos = ciphertext.len().saturating_sub(16);
    let (data, tag) = ciphertext.split_at_mut(tag_pos);
    let tag = aes_gcm::Tag::from_slice(tag);
    cipher
        .decrypt_in_place_detached(nonce, aad, data, tag)
        .map_err(|_| Parse_error::new(Invalid_TLS_Packet, "Decryption failed"))?;
    Ok(ciphertext.len().saturating_sub(16))
}

#[inline]
fn skip_varint(buf: &[u8], pos: usize) -> Option<usize> {
    let first = *buf.get(pos)?;
    let len = match first >> 6 {
        0b00 => 1,
        0b01 => 2,
        0b10 => 4,
        0b11 => 8,
        _ => unreachable!(),
    };
    if pos + len > buf.len() {
        None
    } else {
        Some(len)
    }
}

fn parse_ack_frame(buf: &[u8], pos_in: usize) -> Result<usize, Parse_error> {
    let mut pos = pos_in;
    let (_, len) = parse_varint(buf, pos)?;
    pos += len;
    let (_, len) = parse_varint(buf, pos)?;
    pos += len;
    let (range_count, len) = parse_varint(buf, pos)?;
    pos += len;
    let (_, len) = parse_varint(buf, pos)?;
    pos += len;
    if range_count > (buf.len().saturating_sub(pos) as u64 / 2) {
        return Err(Parse_error::new(
            Invalid_TLS_Packet,
            "Invalid range count: exceeds remaining buffer capacity",
        ));
    }
    for _ in 0..range_count as usize {
        // Gap
        pos +=
            skip_varint(buf, pos).ok_or_else(|| Parse_error::new(Invalid_TLS_Packet, "ACK Gap"))?;
        // Length
        pos += skip_varint(buf, pos)
            .ok_or_else(|| Parse_error::new(Invalid_TLS_Packet, "ACK Range Len"))?;
    }
    Ok(pos - pos_in)
}

fn process_quic_handshake_data(
    is_client: bool,
    packet_info: &mut Packet_info,
    statistics: &mut Statistics,
) -> Result<(), Box<dyn Error>> {
    if is_client {
        packet_info.tls_client.done = true;
        let client_data = packet_info.tls_client.data.clone();
        if !client_data.is_empty() {
            crate::ssl_packet::parse_tls_handshake(&client_data, packet_info, statistics)?;
        }
    } else {
        packet_info.tls_server.done = true;
        let server_data = packet_info.tls_server.data.clone();
        if !server_data.is_empty() {
            crate::ssl_packet::parse_tls_handshake(&server_data, packet_info, statistics)?;
        }
    }
    Ok(())
}

fn ssl_read_packet_number(packet: &[u8], offset: usize, pn_len: usize) -> Result<u32, Parse_error> {
    match pn_len {
        1 => Ok(u32::from(ssl_read_u8(packet, offset)?)),
        2 => Ok(u32::from(ssl_read_u16(packet, offset)?)),
        3 => Ok(ssl_read_u24(packet, offset)?),
        4 => Ok(ssl_read_u32(packet, offset)?),
        _ => Err(Parse_error::new(
            Invalid_TLS_Packet,
            &format!("Packet number length {pn_len}"),
        )),
    }
}

const MAX_HANDSHAKE_SIZE: u64 = 30000;

fn parse_crypto_frame(
    packet_payload: &[u8],
    mut crypto_offset: usize,
    is_client: bool,
    packet_info: &mut Packet_info,
    _frame_type: u64,
) -> Result<usize, Box<dyn Error>> {
    let start_offset = crypto_offset;
    // debug!("Crypto frame");
    let (offset, len) = parse_varint(packet_payload, crypto_offset)?;
    crypto_offset += len;
    let (length, len) = parse_varint(packet_payload, crypto_offset)?;
    crypto_offset += len;
    //debug!("QUIC frame type: {frame_type:x} offset {offset} len: {length} ");
    let crypto_data = ssl_parse_slice(
        packet_payload,
        crypto_offset..crypto_offset + length as usize,
    )?;
    /*debug!(
        "QUIC frame type: {frame_type:x} offset {offset} len: {length} data {:x?}",
        &crypto_data[0..std::cmp::min(4, crypto_data.len())]
    );*/
    let store_data = if is_client {
        packet_info.tls_client.packet_count += 1;
        &mut packet_info.tls_client.data
    } else {
        packet_info.tls_server.packet_count += 1;
        &mut packet_info.tls_server.data
    };
    let total_required = offset.saturating_add(length);

    if total_required > MAX_HANDSHAKE_SIZE {
        return Err(Parse_error::new(
            Invalid_TLS_Packet,
            &format!("Length and offset too large {length} {offset}"),
        )
        .into());
    }
    if store_data.len() < (total_required as usize) {
        store_data.resize(total_required as usize, 0);
    }
    store_data[offset as usize..total_required as usize].copy_from_slice(crypto_data);

    Ok((crypto_offset + length as usize) - start_offset)
}

pub(crate) fn parse_quic(
    packet: &mut [u8],
    config: &Config,
    packet_info_list: &mut Packet_Info_List,
    ts: DateTime<Utc>,
    source_ip: &IpAddr,
    dest_ip: &IpAddr,
    sp: u16,
    dp: u16,
    statistics: &mut Statistics,
    transport_protocol: Transport_Protocol
) -> Result<(), Box<dyn Error>> {
    let is_client = config.ports.contains(&dp);
    let mut offset = 0;
    let flag = ssl_read_u8(packet, offset)?;
    let packet_key = if is_client {
        (*source_ip, *dest_ip, sp, dp)
    } else {
        (*dest_ip, *source_ip, dp, sp)
    };
    let packet_info = packet_info_list
        .packets
        .entry(packet_key)
        .or_insert_with(|| {
            Packet_info::new(
                ts,
                packet_key.2,
                packet_key.3,
                packet_key.0,
                packet_key.1,
                TLS_Protocol::QUIC,
                transport_protocol
            )
        });
    if flag & 0x3 == 0 || flag & 0x80 != 0x80 {
        // not an i=itial packet or not a long header
        return Ok(());
    }
    if flag & 0x80 != 0x80 || flag & 0x40 == 0 {
        // Should check the Fixed Bit (0x40)
        return Ok(());
    }
    if flag & 0x30 == 0x20 {
        //  debug!("Handshake");
        process_quic_handshake_data(is_client, packet_info, statistics)?;
        return Ok(());
    }

    if flag & 0x30 != 0x00 {
        // debug!("Not an initial packet");
        return Ok(());
    }
    let version = ssl_read_u32(packet, offset + 1)?;
    if version != 1 {
        return Err(Parse_error::new(Invalid_TLS_Packet, &format!("Version = {version:x}")).into());
    }
    let d_conn_id_len = ssl_read_u8(packet, offset + 5)?;
    if d_conn_id_len > 20 {
        return Err(Parse_error::new(
            Invalid_TLS_Packet,
            &format!("D conn Id > 20 {d_conn_id_len}"),
        )
        .into());
    }
    offset += 6;
    let d_conn_id = ssl_parse_slice(packet, offset..offset + d_conn_id_len as usize)?;
    offset += d_conn_id_len as usize;
    let s_conn_id_len = ssl_read_u8(packet, offset)?;
    if s_conn_id_len > 20 {
        return Err(Parse_error::new(
            Invalid_TLS_Packet,
            &format!("s conn Id > 20 {s_conn_id_len}"),
        )
        .into());
    }
  //  let _s_conn_id = ssl_parse_slice(packet, offset + 1..offset + 1 + s_conn_id_len as usize)?;
    offset += 1 + s_conn_id_len as usize;
    /*debug!(
        "QUIC d_conn_id {:x} {:x?}, {:x }{:x?} {}",
        d_conn_id_len, d_conn_id, s_conn_id_len, s_conn_id, offset
    );*/

    if packet_info.initial_client_secret.is_empty() && is_client {
        let (client_secret, server_secret) = derive_initial_secret(d_conn_id)?;
        packet_info.initial_client_secret = client_secret;
        packet_info.initial_server_secret = server_secret;
    } else if !is_client && packet_info.initial_server_secret.is_empty() {
        return Err(Parse_error::new(Invalid_TLS_Packet, "Missed initial d_conn_id ").into());
    }
    let secret = if !is_client {
        &packet_info.initial_server_secret
    } else {
        &packet_info.initial_client_secret
    };
    let p_key = derive_packet_keys(secret)?;
    let (token_len, len) = parse_varint(packet, offset)?;
    offset += len + token_len as usize;
    let (len, size) = parse_varint(packet, offset)?;
    offset += size;
    let pn_len = remove_header_protection(packet, offset, &p_key.hp)?;
    let packet_number = ssl_read_packet_number(packet, offset, pn_len)?;

    offset += pn_len;
    //debug!("QUIC packet nr: {packet_number} QUIC len: {len}");
    // debug!("Frame {:x}", packet[offset]);
    if len < pn_len as u64 {
        return Err(Parse_error::new(
            Invalid_TLS_Packet,
            &format!("Invalid packet length {pn_len} "),
        )
        .into());
    }
    let mut payload_slice =
        ssl_parse_slice_mut(packet, offset..offset + len as usize - pn_len)?.to_vec();
    let aad_slice = ssl_parse_slice_mut(packet, 0..offset)?;
    let payload_size = decrypt_quic_payload(
        &p_key.key,
        &p_key.iv,
        u64::from(packet_number),
        &mut payload_slice,
        &aad_slice
    )?;
    //debug!("QUIC packet len {} ", payload_size);
    let mut crypto_offset = 0;
    while crypto_offset < payload_size {
        let (frame_type, len) = parse_varint(&payload_slice, crypto_offset)?;
        if len == 0 {
            break;
        }
        crypto_offset += len;

        if frame_type == 0x06 {
            crypto_offset += parse_crypto_frame(
                &payload_slice,
                crypto_offset,
                is_client,
                packet_info,
                frame_type,
            )?;
        } else if frame_type == 0x02 {
            crypto_offset += parse_ack_frame(&payload_slice, crypto_offset)?;
            // ACK
        } else if frame_type == 0x00 {
            crypto_offset = payload_slice.len();
            // PADDING
        } else {
            break;
        }
    }
    // not interested in short headers, handshakes have long headers

    Ok(())
}
