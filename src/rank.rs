use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering::Equal;
use std::fmt::Debug;
use std::{collections::HashMap, fmt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rank<T>
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
    #[must_use]
    pub fn new(size_in: usize) -> Rank<T> {
        Rank {
            size: size_in,
            rank: HashMap::with_capacity(size_in),
        }
    }
    pub fn set_size(&mut self, size_in: usize) {
        self.size = size_in;
        self.reduce();
    }

    pub fn reduce(&mut self) {
        let n = self.rank.len();
        let k = self.size;

        if n <= k {
            return;
        }
        if k == 0 {
            self.rank.clear();
            return;
        }

        // We need to remove the lowest `n - k` items.
        let remove_count = n - k;

        // Find the cutoff value `t` such that at least `remove_count` items have value <= t.
        // We do this by selecting the `remove_count - 1`-th element in ascending order.
        let mut values: Vec<u128> = self.rank.values().copied().collect();
        let (_, cutoff, _) = values.select_nth_unstable(remove_count - 1);
        let t = *cutoff;

        // Remove everything strictly below the cutoff.
        let to_remove: Vec<T> = self
            .rank
            .iter()
            .filter_map(|(key, &val)| (val < t).then(|| key.clone()))
            .collect();
        for key in &to_remove {
            self.rank.remove(key);
        }

        // If ties at the cutoff remain and we're still above size, remove some `== t` entries.
        // (Arbitrary choice among ties; keeps correctness: final len == self.size.)
        let mut remaining = self.rank.len().saturating_sub(k);
        if remaining > 0 {
            let mut cutoff_keys: Vec<T> = self
                .rank
                .iter()
                .filter_map(|(key, &val)| (val == t).then(|| key.clone()))
                .collect();

            if cutoff_keys.len() > remaining {
                cutoff_keys.truncate(remaining);
            }
            for key in cutoff_keys {
                self.rank.remove(&key);
                remaining -= 1;
                if remaining == 0 {
                    break;
                }
            }
        }
    }

    pub fn remove_lowest(&mut self) -> u128 {
        let min_entry = self.rank.iter().min_by_key(|&(_, v)| v);

        if let Some((k, &v)) = min_entry {
            let key_to_remove = k.clone();
            self.rank.remove(&key_to_remove);
            v
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
                self.remove_lowest() + 1
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

impl<'de, T> Deserialize<'de> for Rank<T>
where
    T: Eq
        + std::hash::Hash
        + fmt::Display
        + serde::Serialize
        + serde::Deserialize<'de>
        + Clone
        + Debug,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Matches `Serialize` which emits a JSON object/map: { key: value, ... }
        let rank = HashMap::<T, u128>::deserialize(deserializer)?;

        // We can't recover the original `size` from the serialized form (it isn't written),
        // so we pick a sensible default consistent with the data we got.
        let size = rank.len();

        Ok(Self { size, rank })
    }
}
