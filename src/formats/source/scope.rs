//! Name bindings for the flow analyses ([`super::payload_flow`],
//! [`super::value_flow`]).

use std::collections::BTreeMap;

/// Name → value bindings, layered over an optional read-only base, itself
/// either a flat map or an enclosing layer.
///
/// Every function body starts from the module-level bindings, and every `if`
/// branch from the bindings before it. Copying those per function or per
/// branch makes an analysis quadratic (functions × globals, or `if`
/// statements × names bound before them); a layer keeps its base borrowed and
/// records only what it binds or unbinds. A `None` in `local` hides a base
/// binding the layer removed.
pub(super) struct Scope<'g, V> {
    base: Option<&'g BTreeMap<String, V>>,
    parent: Option<&'g Scope<'g, V>>,
    local: BTreeMap<String, Option<V>>,
}

impl<V> Default for Scope<'_, V> {
    fn default() -> Self {
        Self {
            base: None,
            parent: None,
            local: BTreeMap::new(),
        }
    }
}

impl<'g, V: Copy> Scope<'g, V> {
    /// An empty layer over the flat bindings `base`.
    pub(super) fn over(base: &'g BTreeMap<String, V>) -> Self {
        Self {
            base: Some(base),
            ..Self::default()
        }
    }

    /// An empty layer over `parent`, which it reads through but never changes.
    pub(super) fn under(parent: &'g Scope<'g, V>) -> Self {
        Self {
            parent: Some(parent),
            ..Self::default()
        }
    }

    /// The binding below this layer.
    fn inherited(&self, name: &str) -> Option<V> {
        match self.parent {
            Some(parent) => parent.get(name),
            None => self.base.and_then(|base| base.get(name).copied()),
        }
    }

    pub(super) fn get(&self, name: &str) -> Option<V> {
        match self.local.get(name) {
            Some(value) => *value,
            None => self.inherited(name),
        }
    }

    pub(super) fn insert(&mut self, name: String, value: V) {
        self.local.insert(name, Some(value));
    }

    pub(super) fn remove(&mut self, name: &str) {
        if self.inherited(name).is_some() {
            self.local.insert(name.to_string(), None);
        } else {
            self.local.remove(name);
        }
    }

    /// What this layer binds, in name order: the only names whose value can
    /// differ from its base. Names it unbinds are skipped.
    pub(super) fn bound(&self) -> impl Iterator<Item = (&String, V)> {
        self.local
            .iter()
            .filter_map(|(name, value)| Some((name, (*value)?)))
    }

    /// Every name this layer binds or unbinds, in name order.
    pub(super) fn names(&self) -> impl Iterator<Item = &String> {
        self.local.keys()
    }

    /// [`Self::names`], consuming the layer.
    pub(super) fn into_names(self) -> impl Iterator<Item = String> {
        self.local.into_keys()
    }

    /// The flattened bindings of a layer with no parent.
    pub(super) fn into_map(self) -> BTreeMap<String, V> {
        let mut map = self.base.cloned().unwrap_or_default();
        for (name, value) in self.local {
            match value {
                Some(value) => map.insert(name, value),
                None => map.remove(&name),
            };
        }
        map
    }
}

#[cfg(test)]
mod tests;
