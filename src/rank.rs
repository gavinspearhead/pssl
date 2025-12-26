use serde::ser::SerializeMap;
use serde::Serialize;
use std::cmp::Ordering::Equal;
use std::fmt::Debug;
use std::{collections::HashMap, fmt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rank<T>
where
    T: Eq + std::hash::Hash + fmt::Display + serde::Serialize + Clone + Debug,
{
    size: usize,
    rank: HashMap<T, u128>,
}

impl<T> Default for Rank<T>
where
    T: Eq + std::hash::Hash + fmt::Display + serde::Serialize + Clone + Debug,
{
    fn default() -> Self {
        Self {
            rank: HashMap::new(),
            size: Default::default(),
        }
    }
}

impl<T> Rank<T>
where
    T: Eq + std::hash::Hash + fmt::Display + serde::Serialize + Clone + Debug,
{
    pub fn new(size_in: usize) -> Rank<T> {
        Rank {
            size: size_in,
            rank: HashMap::with_capacity(size_in),
        }
    }

    pub fn remove_lowest(&mut self) -> u128 {
        let mut min_key = None;
        let mut min_val: u128 = 0;
        let mut max_val: u128 = 0;

        for (k, v) in &self.rank {
            if min_val == 0 || *v < min_val {
                min_val = *v;
                min_key = Some(k);
            }
            if *v > max_val {
                max_val = *v;
            }
        }
        if let Some(k) = min_key {
            //debug!("Remove k={} minv={} maxv={}", k, min_val, max_val);
            self.rank.remove(&k.clone());
            min_val.saturating_mul(2).saturating_add(max_val) / 3
        } else {
            0
        }
    }

    pub fn add(&mut self, element: &T) {
        if let Some(elem) = self.rank.get_mut(element) {
            *elem += 1;
            //debug!("{:?}: {:?}", element, *elem);
        } else {
            // debug!("{:?}: 0", element);
            let val = if self.rank.len() >= self.size {
                self.remove_lowest().max(1)
            } else {
                1
            };
            self.rank.insert(element.clone(), val);
        }
    }
}

impl<T> fmt::Display for Rank<T>
where
    T: Eq + std::hash::Hash + fmt::Display + serde::Serialize + Default + Clone + Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut l = Vec::new();
        for (k, v) in &self.rank {
            l.push((k, v));
        }
        l.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(Equal));
        for (k, v) in &l {
            writeln!(f, "{k}: {v}").expect("Cannot write output format ");
        }
        write!(f, "")
    }
}

impl<T> Serialize for Rank<T>
where
    T: Eq + std::hash::Hash + fmt::Display + serde::Serialize + Clone + Debug,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut l: Vec<_> = self.rank.iter().collect(); // Collect references to entries
        l.sort_unstable_by(|a, b| b.1.cmp(a.1));

        let mut map = serializer.serialize_map(Some(l.len()))?;
        for (key, value) in l {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}
