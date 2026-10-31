//! Exact named native values for owner configuration and mutable policy accounting.
use crate::*;

/// Generic owner-signed policy configuration. Unknown keys and native values are preserved.
/// JSON values are canonical base64 ScVal XDR; callers can construct ScVal values directly.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NativeValues(pub std::collections::BTreeMap<String, ScVal>);
impl Serialize for NativeValues {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::Error;
        let encoded = self
            .0
            .iter()
            .map(|(name, value)| xdr(value).map(|value| (name.clone(), value)))
            .collect::<Result<std::collections::BTreeMap<_, _>>>()
            .map_err(S::Error::custom)?;
        encoded.serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for NativeValues {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct NamedValues;
        impl<'de> serde::de::Visitor<'de> for NamedValues {
            type Value = NativeValues;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("unique names mapped to canonical base64 native XDR")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut entries: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                use serde::de::Error;
                let mut values = std::collections::BTreeMap::new();
                while let Some((name, encoded)) = entries.next_entry::<String, String>()? {
                    if values.contains_key(&name) {
                        return Err(A::Error::custom("Duplicate named native value"));
                    }
                    let value: ScVal = read(&encoded).map_err(A::Error::custom)?;
                    if xdr(&value).map_err(A::Error::custom)? != encoded {
                        return Err(A::Error::custom(
                            "NativeValues value requires canonical native XDR",
                        ));
                    }
                    values.insert(name, value);
                }
                Ok(NativeValues(values))
            }
        }
        deserializer.deserialize_map(NamedValues)
    }
}
impl NativeValues {
    pub(crate) fn value(&self) -> Result<ScVal> {
        let fields = self
            .0
            .iter()
            .map(|(name, value)| {
                Ok(ScMapEntry {
                    key: ScVal::String(ScString(name.as_bytes().to_vec().try_into().map_err(err)?)),
                    val: value.clone(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(ScVal::Map(Some(fields.try_into().map_err(err)?)))
    }
}

impl NativeValues {
    pub(crate) fn from_value(value: &ScVal) -> Result<Self> {
        let ScVal::Map(Some(entries)) = value else {
            return Err("Expected a named native-value map".into());
        };
        let mut values = std::collections::BTreeMap::new();
        for entry in entries.iter() {
            let ScVal::String(name) = &entry.key else {
                return Err("Named native values require String keys".into());
            };
            let name = String::from_utf8(name.0.to_vec()).map_err(err)?;
            if values.insert(name, entry.val.clone()).is_some() {
                return Err("Duplicate named native value".into());
            }
        }
        Ok(Self(values))
    }
}

impl NativeValues {
    /// Decode one requested source scalar without coercion. Missing is None; an unsupported
    /// type or invalid UTF-8 is an error. Unread values remain untouched in the native map.
    pub fn scalar(&self, name: &str) -> Result<Option<allowit_policy_sdk::PolicyScalar>> {
        use allowit_policy_sdk::PolicyScalar;
        self.0
            .get(name)
            .map(|value| match value {
                ScVal::U64(value) => Ok(PolicyScalar::U64(*value)),
                ScVal::Bool(value) => Ok(PolicyScalar::Bool(*value)),
                ScVal::String(value) => String::from_utf8(value.0.to_vec())
                    .map(PolicyScalar::String)
                    .map_err(err),
                _ => Err("Requested native value is not a supported source scalar".into()),
            })
            .transpose()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duplicate_json_names_reject_instead_of_replacing_owner_values() {
        let first = xdr(&ScVal::U64(1)).unwrap();
        let second = xdr(&ScVal::U64(2)).unwrap();
        let duplicate = format!(r#"{{"limit":"{first}","limit":"{second}"}}"#);
        assert!(serde_json::from_str::<NativeValues>(&duplicate).is_err());
        assert!(serde_json::from_str::<NativeValues>(&format!(r#"{{"limit":"{first}"}}"#)).is_ok());
    }
    #[test]
    fn invalid_utf8_names_reject_and_raw_values_are_lossless_until_typed_access() {
        let bad = ScVal::String(ScString(vec![0xff].try_into().unwrap()));
        let malformed = ScVal::Map(Some(
            vec![ScMapEntry {
                key: bad.clone(),
                val: ScVal::U64(1),
            }]
            .try_into()
            .unwrap(),
        ));
        assert!(NativeValues::from_value(&malformed).is_err());
        let values = NativeValues(std::collections::BTreeMap::from([
            ("opaque_text".into(), bad.clone()),
            ("not_u64".into(), ScVal::U32(1)),
            ("exact".into(), ScVal::U64(u64::MAX)),
        ]));
        let restored: NativeValues =
            serde_json::from_value(serde_json::to_value(&values).unwrap()).unwrap();
        assert_eq!(restored, values);
        assert_eq!(restored.0["opaque_text"], bad);
        assert!(restored.scalar("opaque_text").is_err());
        assert!(restored.scalar("not_u64").is_err());
        assert_eq!(
            restored.scalar("exact").unwrap(),
            Some(allowit_policy_sdk::PolicyScalar::U64(u64::MAX))
        );
        assert_eq!(restored.scalar("missing").unwrap(), None);
    }
}
