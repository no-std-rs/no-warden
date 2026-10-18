//! A small safe fixed-capacity sequence, including allocation-free serde support.
use core::fmt;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, SeqAccess, Visitor},
    ser::SerializeSeq,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedList<T, const N: usize> {
    entries: [Option<T>; N],
    len: usize,
}

impl<T, const N: usize> BoundedList<T, N> {
    pub fn new() -> Self {
        Self {
            entries: core::array::from_fn(|_| None),
            len: 0,
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Returns the original element if the sequence is full.
    pub fn push(&mut self, value: T) -> Result<(), T> {
        if self.len == N {
            return Err(value);
        }
        self.entries[self.len] = Some(value);
        self.len += 1;
        Ok(())
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.entries[..self.len].iter().filter_map(Option::as_ref)
    }

    pub fn get(&self, index: usize) -> Option<&T> {
        self.entries.get(index).and_then(Option::as_ref)
    }
}

impl<T, const N: usize> Default for BoundedList<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Serialize, const N: usize> Serialize for BoundedList<T, N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.len))?;
        for value in self.iter() {
            sequence.serialize_element(value)?;
        }
        sequence.end()
    }
}

impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for BoundedList<T, N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ListVisitor<T, const N: usize>(core::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for ListVisitor<T, N> {
            type Value = BoundedList<T, N>;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "a sequence containing at most {N} entries")
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut result = BoundedList::new();
                while let Some(value) = sequence.next_element()? {
                    result
                        .push(value)
                        .map_err(|_| de::Error::custom("sequence exceeds fixed capacity"))?;
                }
                Ok(result)
            }
        }
        deserializer.deserialize_seq(ListVisitor::<T, N>(core::marker::PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn serde_rejects_overflow_and_round_trips() {
        let values: BoundedList<&str, 2> = serde_json::from_str(r#"["one","two"]"#).unwrap();
        assert_eq!(values.get(1), Some(&"two"));
        assert_eq!(serde_json::to_string(&values).unwrap(), r#"["one","two"]"#);
        assert!(serde_json::from_str::<BoundedList<&str, 2>>(r#"["a","b","c"]"#).is_err());
        assert!(serde_json::from_str::<BoundedList<u8, 0>>("[1]").is_err());
    }
}
