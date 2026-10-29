use allowit_wallet_protocol::Spent;
use soroban_sdk::{BytesN, Env, TryFromVal, Val, contracttype};

/// One persistent policy object, separate from custody authority, ordering and replay keys.
#[contracttype]
#[derive(Clone)]
enum Key {
    Spent(BytesN<32>),
}

/// Load and final-commit capability. Functional policy helpers do not write persistent storage.
pub(crate) struct NativePolicyStorage<'a> {
    pub(crate) env: &'a Env,
    pub(crate) policy_instance: BytesN<32>,
}
impl NativePolicyStorage<'_> {
    fn key(&self) -> Key {
        Key::Spent(self.policy_instance.clone())
    }

    /// Read the full raw map. Existing empty data remains distinct from true absence.
    pub(crate) fn snapshot(&self) -> Result<Option<Spent>, ()> {
        let key = self.key();
        let Some(raw) = self.env.storage().persistent().get::<_, Val>(&key) else {
            return Ok(None);
        };
        let map = Spent::try_from_val(self.env, &raw).map_err(|_| ())?;
        if !allowit_wallet_protocol::named_values_valid(self.env, &map) {
            return Err(());
        }
        let ttl = self.env.storage().max_ttl();
        self.env
            .storage()
            .persistent()
            .extend_ttl(&key, ttl / 2, ttl);
        Ok(Some(map))
    }

    /// Commit only changed final data. No empty entry or persistent dirty marker is created for an unused map.
    pub(crate) fn commit(&self, initial: &Option<Spent>, final_spent: &Spent) -> bool {
        if initial.as_ref().is_some_and(|value| value == final_spent)
            || (initial.is_none() && final_spent.is_empty())
        {
            return false;
        }
        let key = self.key();
        self.env.storage().persistent().set(&key, final_spent);
        let ttl = self.env.storage().max_ttl();
        self.env
            .storage()
            .persistent()
            .extend_ttl(&key, ttl / 2, ttl);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use allowit_wallet_protocol::{Grant, PolicyValue};
    use soroban_sdk::{
        Bytes, IntoVal, String, contract, contracterror, contractimpl, testutils::Ledger,
    };
    #[contract]
    struct Harness;
    #[contracterror]
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    #[repr(u32)]
    enum Failure {
        Denied = 1,
    }
    #[contractimpl]
    impl Harness {
        pub fn get(env: Env, instance: BytesN<32>) -> Option<Spent> {
            NativePolicyStorage {
                env: &env,
                policy_instance: instance,
            }
            .snapshot()
            .unwrap()
        }
        pub fn put(
            env: Env,
            instance: BytesN<32>,
            value: Spent,
            fail: bool,
        ) -> Result<bool, Failure> {
            let storage = NativePolicyStorage {
                env: &env,
                policy_instance: instance,
            };
            let initial = storage.snapshot().unwrap();
            let changed = storage.commit(&initial, &value);
            if fail {
                return Err(Failure::Denied);
            }
            Ok(changed)
        }
    }
    fn map(env: &Env, value: u64) -> Spent {
        let mut map = Spent::new(env);
        map.set(String::from_str(env, "nonce"), value.into_val(env));
        map
    }
    fn value(env: &Env, map: &Spent) -> u64 {
        u64::try_from_val(env, &map.get(String::from_str(env, "nonce")).unwrap()).unwrap()
    }
    #[test]
    fn namespace_and_final_commit_rollback() {
        let env = Env::default();
        let wallet = env.register(Harness, ());
        let a = BytesN::from_array(&env, &[1; 32]);
        let b = BytesN::from_array(&env, &[2; 32]);
        let c = HarnessClient::new(&env, &wallet);
        assert!(c.try_put(&a, &map(&env, 9), &true).is_err());
        assert_eq!(c.get(&a), None);
        assert!(c.put(&a, &map(&env, 9), &false));
        assert_eq!(value(&env, &c.get(&a).unwrap()), 9);
        assert_eq!(c.get(&b), None);
        assert!(c.try_put(&a, &Spent::new(&env), &true).is_err());
        assert_eq!(value(&env, &c.get(&a).unwrap()), 9);
        env.as_contract(&wallet, || assert!(!env.storage().instance().has(&0u32)));
        assert!(c.put(&a, &Spent::new(&env), &false));
        assert!(c.get(&a).unwrap().is_empty());
    }
    #[test]
    fn unchanged_or_unused_empty_maps_do_not_write_data() {
        let env = Env::default();
        let wallet = env.register(Harness, ());
        let a = BytesN::from_array(&env, &[1; 32]);
        let c = HarnessClient::new(&env, &wallet);
        assert!(!c.put(&a, &Spent::new(&env), &false));
        assert_eq!(c.get(&a), None);
        assert!(c.put(&a, &map(&env, 9), &false));
        assert!(!c.put(&a, &map(&env, 9), &false));
        assert_eq!(value(&env, &c.get(&a).unwrap()), 9);
    }
    #[test]
    fn persistent_expiry_preserves_original_map() {
        let env = Env::default();
        let wallet = env.register(Harness, ());
        let a = BytesN::from_array(&env, &[1; 32]);
        let c = HarnessClient::new(&env, &wallet);
        c.put(&a, &map(&env, 9), &false);
        env.ledger()
            .with_mut(|l| l.sequence_number += l.max_entry_ttl + 1);
        assert_eq!(value(&env, &c.get(&a).unwrap()), 9);
    }
    #[test]
    fn invalid_native_object_is_not_absence() {
        let env = Env::default();
        let wallet = env.register(Harness, ());
        let a = BytesN::from_array(&env, &[1; 32]);
        env.as_contract(&wallet, || {
            env.storage()
                .persistent()
                .set(&Key::Spent(a.clone()), &99u64);
            assert!(
                NativePolicyStorage {
                    env: &env,
                    policy_instance: a
                }
                .snapshot()
                .is_err()
            );
        });
    }
    #[test]
    fn scalar_helpers_preserve_other_raw_values_without_coercion() {
        let env = Env::default();
        let mut original = Grant::new(&env);
        let bytes = Bytes::from_slice(&env, &[1, 2, 3]);
        original.set(String::from_str(&env, "custom_bytes"), bytes.into_val(&env));
        let mut final_map = original.clone();
        final_map.set(
            String::from_str(&env, "count"),
            PolicyValue::U64(9).into_raw(&env),
        );
        assert_eq!(
            Bytes::try_from_val(
                &env,
                &final_map
                    .get(String::from_str(&env, "custom_bytes"))
                    .unwrap()
            )
            .unwrap(),
            bytes
        );
        assert!(
            PolicyValue::from_raw(
                &env,
                &original
                    .get(String::from_str(&env, "custom_bytes"))
                    .unwrap()
            )
            .is_err()
        );
        assert_eq!(
            PolicyValue::from_raw(
                &env,
                &final_map.get(String::from_str(&env, "count")).unwrap()
            ),
            Ok(PolicyValue::U64(9))
        );
        assert!(PolicyValue::from_raw(&env, &9i128.into_val(&env)).is_err());
    }
}

#[cfg(test)]
mod utf8_tests {
    extern crate std;
    use soroban_sdk::{Env, String};
    #[test]
    fn name_validation_handles_long_names_and_utf8_chunk_boundaries() {
        let env = Env::default();
        let mut name = std::vec![b'a';255];
        name.extend_from_slice("€".as_bytes());
        name.extend_from_slice(&std::vec![b'b';900]);
        assert!(allowit_wallet_protocol::utf8_string(&String::from_bytes(
            &env, &name
        )));
        assert!(!allowit_wallet_protocol::utf8_string(&String::from_bytes(
            &env,
            &[0xe2, 0x82]
        )));
        assert!(!allowit_wallet_protocol::utf8_string(&String::from_bytes(
            &env,
            &[0xed, 0xa0, 0x80]
        )));
    }
}
