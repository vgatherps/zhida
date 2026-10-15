//! Test-only net_pcap vdev and classic microsecond pcap writer.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

use zhida_dpdk_sys::{rte_eth_dev_get_port_by_name, rte_vdev_init, rte_vdev_uninit};

/// A net_pcap vdev reading `rx_pcap` and writing `tx_pcap`. Declare it before
/// the Port it backs so the Port drops first. Dropped without `close`, it
/// removes the vdev; outside a panic it then fails the test.
pub struct PcapVdev {
    vdev: CString,
    port_id: u16,
    closed: bool,
}

impl PcapVdev {
    pub fn new(vdev: &CStr, rx_pcap: &Path, tx_pcap: &Path) -> Self {
        let args = CString::new(format!(
            "rx_pcap={},tx_pcap={}",
            rx_pcap.to_str().unwrap(),
            tx_pcap.to_str().unwrap()
        ))
        .unwrap();
        assert_eq!(unsafe { rte_vdev_init(vdev.as_ptr(), args.as_ptr()) }, 0);
        let mut pcap = Self {
            vdev: vdev.to_owned(),
            port_id: u16::MAX,
            closed: false,
        };
        assert_eq!(
            unsafe { rte_eth_dev_get_port_by_name(vdev.as_ptr(), &mut pcap.port_id) },
            0
        );
        pcap
    }

    pub fn port_id(&self) -> u16 {
        self.port_id
    }

    /// Remove the vdev after the Port has closed.
    pub fn close(mut self) {
        assert_eq!(unsafe { rte_vdev_uninit(self.vdev.as_ptr()) }, 0);
        self.closed = true;
    }
}

impl Drop for PcapVdev {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        unsafe { rte_vdev_uninit(self.vdev.as_ptr()) };
        if !std::thread::panicking() {
            panic!(
                "PcapVdev {} dropped without close",
                self.vdev.to_string_lossy()
            );
        }
    }
}

/// Write little-endian pcap v2.4 with microsecond timestamps and Ethernet frames.
pub fn write_pcap(path: &Path, records: &[(u32, u32, &[u8])]) -> io::Result<()> {
    let mut file = BufWriter::new(File::create(path)?);
    file.write_all(&0xa1b2c3d4_u32.to_le_bytes())?;
    file.write_all(&2_u16.to_le_bytes())?;
    file.write_all(&4_u16.to_le_bytes())?;
    for value in [0_u32, 0, 65535, 1] {
        file.write_all(&value.to_le_bytes())?;
    }
    for &(ts_sec, ts_usec, frame) in records {
        let len = u32::try_from(frame.len()).expect("pcap frame length fits u32");
        for value in [ts_sec, ts_usec, len, len] {
            file.write_all(&value.to_le_bytes())?;
        }
        file.write_all(frame)?;
    }
    file.flush()
}
