use chrono::{DateTime, Datelike as _, Timelike as _, Utc};
use serde::{Deserialize, Serialize};
use tracing::debug;

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub(crate) struct Bucket {
    last_post: usize,
    last_group: usize,
    items: Vec<u128>,
}

impl Bucket {
    fn new(size: usize) -> Bucket {
        Bucket {
            items: vec![0; size],
            last_post: 0,
            last_group: 0,
        }
    }

    #[inline]
    fn get_item(&self) -> &Vec<u128> {
        self.items.as_ref()
    }
    fn add(&mut self, position: u32, count: u128, group_val: u32) {
        let pos = position as usize;
        let len = self.items.len();
        if pos >= len {
            debug!("Cannot update item");
            return;
        }
        let group = group_val as usize;

        if pos == self.last_post && group == self.last_group {
            self.items[pos] += count;
        } else if group == self.last_group {
            if pos > self.last_post {
                self.items[self.last_post + 1..pos].fill(0);
            } else {
                self.items[0..pos].fill(0);
            }
            self.items[pos] = count;
        } else if group == self.last_group + 1 {
            self.items[self.last_post + 1..len].fill(0);
            self.items[0..pos].fill(0);
            self.items[pos] = count;
        } else {
            self.items.fill(0);
            self.items[pos] = count;
        }
        self.last_post = pos;
        self.last_group = group;
    }
}

#[cfg(test)]
mod tests {
    use super::Bucket;
    #[test]
    fn test_bucket() {
        let mut hour = Bucket::new(12);
        let mut v = vec![0; 12];

        hour.add(1, 1, 1);
        hour.add(1, 1, 1);
        v[1] = 2;
        assert_eq!(hour.items, v);
        hour.add(2, 1, 1);
        hour.add(3, 1, 1);
        v[1] = 2;
        v[2] = 1;
        v[3] = 1;
        assert_eq!(hour.items, v);
        hour.add(10, 1, 1);
        v[10] = 1;
        assert_eq!(hour.items, v);
        hour.add(3, 1, 2);
        v[1] = 0;
        v[2] = 0;
        v[3] = 1;
        assert_eq!(hour.items, v);
        hour.add(4, 1, 2);
        v[4] = 1;
        assert_eq!(hour.items, v);
        hour.add(2, 1, 4);
        hour.add(6, 1, 4);
        hour.add(16, 1, 4);
        v = vec![0; 12];
        v[2] = 1;
        v[6] = 1;
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) enum STAT_ITEM {
    MONTH,
    MINUTE,
    HOUR,
    DAY,
    SECOND,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub(crate) struct Time_stats {
    pub(crate) per_month: Bucket,
    pub(crate) per_minute: Bucket,
    pub(crate) per_hour: Bucket,
    pub(crate) per_day: Bucket,
    pub(crate) per_second: Bucket,
}

impl Time_stats {
    pub(crate) fn new() -> Time_stats {
        Time_stats {
            per_minute: Bucket::new(60),
            per_hour: Bucket::new(24),
            per_day: Bucket::new(31),
            per_month: Bucket::new(12),
            per_second: Bucket::new(60),
        }
    }

    pub(crate) fn add(&mut self, time_stamp: DateTime<Utc>, count: u128) {
        let m = time_stamp.minute();
        let s = time_stamp.second();
        let h = time_stamp.hour();
        let d = time_stamp.day0();
        let mon = time_stamp.month0();
        let year = time_stamp.year() as u32;
        self.per_month.add(mon, count, year);
        self.per_day.add(d, count, mon);
        self.per_minute.add(m, count, h);
        self.per_hour.add(h, count, d);
        self.per_second.add(s, count, m);
    }

    pub(crate) fn get_item(&self, stat_item: &STAT_ITEM) -> &Vec<u128> {
        match stat_item {
            STAT_ITEM::MONTH => self.per_month.get_item(),
            STAT_ITEM::MINUTE => self.per_minute.get_item(),
            STAT_ITEM::HOUR => self.per_hour.get_item(),
            STAT_ITEM::DAY => self.per_day.get_item(),
            STAT_ITEM::SECOND => self.per_second.get_item(),
        }
    }
}
