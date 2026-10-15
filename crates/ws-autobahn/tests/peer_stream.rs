use std::io::Read;

use zhida_test_kit::pair::{self, App, Side};
use zhida_test_kit::with_eal;

#[path = "common/stream.rs"]
mod stream;

#[zhida_test_support::pinned_test]
fn peer_keeps_frame_remainder_between_stream_borrows() {
    with_eal(|eal| {
        let mut pair = pair::new_pair(eal, ["peerlefta", "peerleftb"]);
        let ([client, server], _) = pair::establish(&mut pair, Side::A);
        let payload = pair::pattern(200, 51);
        assert_eq!(pair.a.tcp_mut(&client).send_slice(&payload), Ok(payload.len()));
        pair.drive(|_, _| {}, |_, b| {
            if b.tcp(&server).recv_queue() == payload.len() { App::Done } else { App::Idle }
        });
        let mut handle = Some(server);
        let mut pending = None;
        let mut buffer = [0; 256];
        stream::with_stream(&mut pair.b, &mut handle, &mut pending, |stream| {
            assert_eq!(stream.read(&mut buffer[..5]).unwrap(), 5);
        });
        assert_eq!(&buffer[..5], &payload[..5]);
        assert_eq!(pair.b.tcp(handle.as_ref().unwrap()).held_frames().count(), 1);
        stream::with_stream(&mut pair.b, &mut handle, &mut pending, |stream| {
            assert_eq!(stream.read(&mut buffer).unwrap(), 195);
        });
        assert_eq!(&buffer[..195], &payload[5..]);
        assert!(pending.is_none());
        assert_eq!(pair.b.tcp(handle.as_ref().unwrap()).held_frames().count(), 0);
        assert_eq!(pair.close(), 0);
    });
}
