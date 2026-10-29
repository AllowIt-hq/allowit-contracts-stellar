use soroban_sdk::{Env, IntoVal, TryFromVal, Val};

/// Read or initialize one persistent entry and renew its lifetime.
pub(super) fn load<K, V>(env: &Env, key: &K, initial: Option<&V>) -> Option<V>
where
    K: IntoVal<Env, Val>,
    V: Clone + IntoVal<Env, Val> + TryFromVal<Env, Val>,
{
    let value = env.storage().persistent().get(key).or_else(|| {
        initial.map(|value| {
            env.storage().persistent().set(key, value);
            value.clone()
        })
    });
    if value.is_some() {
        let ttl = env.storage().max_ttl();
        env.storage().persistent().extend_ttl(key, ttl / 2, ttl);
    }
    value
}
