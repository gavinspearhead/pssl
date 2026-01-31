use chrono::{DateTime, Utc};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

pub(crate) type QueuedPacket = Option<(Vec<u8>, DateTime<Utc>)>;
#[derive(Debug, Clone, Default)]
pub(crate) struct Packet_Queue {
    queue: Arc<Mutex<VecDeque<QueuedPacket>>>,
}

impl Packet_Queue {
    const INITIAL_QUEUE_SIZE: usize = 32;
    const MAX_QUEUE_SIZE: usize = 1024;
    pub fn new() -> Packet_Queue {
        Packet_Queue {
            queue: Arc::new(Mutex::new(VecDeque::with_capacity(
                Self::INITIAL_QUEUE_SIZE,
            ))),
        }
    }
    #[inline]
    pub fn push_back(&self, packet: QueuedPacket) {
        let mut queue = self.queue.lock().unwrap();
        if queue.len() < Self::MAX_QUEUE_SIZE {
            queue.push_back(packet);
        }
    }
    #[inline]
    pub fn pop_front(&self) -> Option<QueuedPacket> {
        self.queue.lock().unwrap().pop_front()
    }
}
