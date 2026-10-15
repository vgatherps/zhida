//! Integration tests mimicking realistic TX and RX packet processing paths.

use zhida_buffer::PoolManager;

const IP_HEADER_LEN: u16 = 20;
const TCP_HEADER_LEN: u16 = 20;

#[zhida_test_support::pinned_test]
fn test_tx_path_single_segment() {
    let pool = PoolManager::new(256);
    let mut mbuf = pool.alloc_with_len(1000).unwrap();
    mbuf.data_mut().fill(0xDD);

    // Prepend TCP header
    mbuf.prepend(TCP_HEADER_LEN).unwrap().copy_from_slice(&{
        let mut hdr = [0u8; TCP_HEADER_LEN as usize];
        hdr[0..2].copy_from_slice(&80u16.to_be_bytes());
        hdr[2..4].copy_from_slice(&443u16.to_be_bytes());
        hdr[4..8].copy_from_slice(&1000u32.to_be_bytes());
        hdr
    });

    // Prepend IP header
    mbuf.prepend(IP_HEADER_LEN).unwrap().copy_from_slice(&{
        let mut hdr = [0u8; IP_HEADER_LEN as usize];
        hdr[0] = 0x45;
        hdr
    });

    assert_eq!(mbuf.len(), IP_HEADER_LEN + TCP_HEADER_LEN + 1000);

    let data = mbuf.data();
    assert_eq!(data[0], 0x45);
    assert_eq!(&data[20..22], &80u16.to_be_bytes());
}

#[zhida_test_support::pinned_test]
fn test_tx_path_with_retransmit() {
    let pool = PoolManager::new(256);
    let mut mbuf = pool.alloc_with_len(500).unwrap();
    mbuf.data_mut().fill(0xBB);

    mbuf.prepend(TCP_HEADER_LEN).unwrap().fill(0x11);
    mbuf.prepend(IP_HEADER_LEN).unwrap().fill(0x22);

    let retransmit_copy = mbuf.share();

    assert_eq!(mbuf.len(), retransmit_copy.len());

    let sent_bytes: Vec<u8> = mbuf.data().to_vec();
    drop(mbuf);

    let retransmit_bytes: Vec<u8> = retransmit_copy.data().to_vec();
    assert_eq!(sent_bytes, retransmit_bytes);
}

#[zhida_test_support::pinned_test]
fn test_rx_path_header_parsing() {
    let pool = PoolManager::new(256);
    let total_len = IP_HEADER_LEN + TCP_HEADER_LEN + 500;
    let mut mbuf = pool.alloc_with_len(total_len).unwrap();

    let data = mbuf.data_mut();
    data[0] = 0x45;
    data[1..IP_HEADER_LEN as usize].fill(0);
    data[IP_HEADER_LEN as usize..(IP_HEADER_LEN + TCP_HEADER_LEN) as usize].fill(0x11);
    data[(IP_HEADER_LEN + TCP_HEADER_LEN) as usize..].fill(0xDD);

    let ip_header_len = ((mbuf.data()[0] & 0x0F) * 4) as u16;
    assert_eq!(ip_header_len, 20);
    mbuf.adj(ip_header_len);

    mbuf.adj(TCP_HEADER_LEN);

    assert_eq!(mbuf.len(), 500);
    assert!(mbuf.data().iter().all(|&b| b == 0xDD));
}

#[zhida_test_support::pinned_test]
fn test_refcount_through_tx_flow() {
    let pool = PoolManager::new(256);
    let mut mbuf = pool.alloc_with_len(500).unwrap();
    assert_eq!(mbuf.refcount(), 1);

    mbuf.prepend(TCP_HEADER_LEN).unwrap();
    mbuf.prepend(IP_HEADER_LEN).unwrap();

    assert_eq!(mbuf.refcount(), 1);

    let retransmit = mbuf.share();
    assert_eq!(mbuf.refcount(), 2);

    drop(mbuf);
    assert_eq!(retransmit.refcount(), 1);

    assert!(retransmit.len() > 0);
}
