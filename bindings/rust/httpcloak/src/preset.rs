use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use http::Version;
use httpcloak_sys as sys;
use serde::Deserialize;

use crate::error::{Error, Result};
use crate::ffi::{self, cpath, cstring};

/// What a preset supports, from [`available_presets`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct PresetInfo {
    /// The HTTP versions the preset can speak.
    pub protocols: Vec<Version>,
}

impl PresetInfo {
    pub fn supports_http3(&self) -> bool {
        self.protocols.contains(&Version::HTTP_3)
    }
}

/// Every built-in preset, by name: the [`presets`](crate::presets) constants
/// and the older spellings the library still accepts. Custom presets
/// registered with [`load_preset`] are not listed.
pub fn available_presets() -> Result<BTreeMap<String, PresetInfo>> {
    #[derive(Deserialize)]
    struct Wire {
        #[serde(default)]
        protocols: Vec<String>,
    }
    // SAFETY: plain call; the result is ours to free.
    let json = unsafe { ffi::take_string(sys::httpcloak_available_presets()) };
    let wire: BTreeMap<String, Wire> = ffi::parse_json(&ffi::checked(json, "listing the presets")?, "the preset list")?;
    Ok(wire
        .into_iter()
        .map(|(name, w)| {
            let protocols = w.protocols.iter().map(|p| crate::response::version(p)).collect();
            (name, PresetInfo { protocols })
        })
        .collect())
}

/// The full, resolved definition of preset `name` as canonical JSON: every
/// TLS, HTTP/2, HTTP/3 and header setting it ends up with, inheritance
/// flattened. Works for aliases and custom presets too.
pub fn describe_preset(name: &str) -> Result<String> {
    let c_name = cstring(name, "the preset name")?;
    // SAFETY: a valid NUL-terminated string; the result is ours to free.
    let json = unsafe { ffi::take_string(sys::httpcloak_describe_preset(c_name.as_ptr())) };
    ffi::checked(json, "describing the preset").map_err(|e| Error::invalid_input(e.message()))
}

/// Registers a custom preset from its JSON definition and returns its name,
/// usable from then on wherever a preset name is. Fails if the name is taken;
/// [`unregister_preset`] it first to replace it. The format is described at
/// <https://httpcloak.dev/docs/reference/json-preset-spec>.
pub fn load_preset(json: &str) -> Result<String> {
    let c_json = cstring(json, "the preset JSON")?;
    // SAFETY: a valid NUL-terminated string; the result is ours to free.
    let result = unsafe { ffi::take_string(sys::httpcloak_preset_load_json(c_json.as_ptr())) };
    registered_name(result)
}

/// As [`load_preset`], from a file.
pub fn load_preset_file(path: impl AsRef<Path>) -> Result<String> {
    let c_path = cpath(path.as_ref(), "the preset path")?;
    // SAFETY: a valid NUL-terminated string; the result is ours to free.
    let result = unsafe { ffi::take_string(sys::httpcloak_preset_load_file(c_path.as_ptr())) };
    registered_name(result)
}

fn registered_name(result: Option<String>) -> Result<String> {
    #[derive(Deserialize)]
    struct Name {
        name: String,
    }
    let json = ffi::checked(result, "registering the preset").map_err(|e| Error::invalid_input(e.message()))?;
    Ok(ffi::parse_json::<Name>(&json, "the registered preset")?.name)
}

/// Removes a custom preset. Sessions already using it keep their fingerprint.
///
/// For a built-in preset defined in JSON (most of the recent ones), this
/// removes it too, and its name then falls back to the previous version.
pub fn unregister_preset(name: &str) -> Result<()> {
    let c_name = cstring(name, "the preset name")?;
    // SAFETY: a valid NUL-terminated string, only read during the call.
    unsafe { sys::httpcloak_preset_unregister(c_name.as_ptr()) };
    Ok(())
}

/// A set of presets to rotate through, from a pool definition.
///
/// Loading a pool registers its presets under their names, replacing any
/// already registered under the same names; dropping it unregisters them.
/// Sessions created from them keep their fingerprint.
///
/// ```no_run
/// # fn main() -> httpcloak::Result<()> {
/// let pool = httpcloak::PresetPool::from_file("pool.json")?;
/// let session = httpcloak::Session::builder().preset(pool.pick()?).build()?;
/// # Ok(())
/// # }
/// ```
pub struct PresetPool {
    handle: i64,
}

impl PresetPool {
    /// Loads a pool from its JSON definition.
    pub fn from_json(json: &str) -> Result<PresetPool> {
        let c_json = cstring(json, "the pool JSON")?;
        // SAFETY: a valid NUL-terminated string; the result is ours to free.
        let result = unsafe { ffi::take_string(sys::httpcloak_pool_load_json(c_json.as_ptr())) };
        PresetPool::from_result(result)
    }

    /// Loads a pool from a file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<PresetPool> {
        let c_path = cpath(path.as_ref(), "the pool path")?;
        // SAFETY: a valid NUL-terminated string; the result is ours to free.
        let result = unsafe { ffi::take_string(sys::httpcloak_pool_load_file(c_path.as_ptr())) };
        PresetPool::from_result(result)
    }

    fn from_result(result: Option<String>) -> Result<PresetPool> {
        #[derive(Deserialize)]
        struct Handle {
            handle: i64,
        }
        let json = ffi::checked(result, "loading the pool").map_err(|e| Error::invalid_input(e.message()))?;
        let handle = ffi::parse_json::<Handle>(&json, "the pool handle")?.handle;
        if handle <= 0 {
            return Err(Error::new_other("the library returned no pool"));
        }
        Ok(PresetPool { handle })
    }

    fn name_from(&self, get: unsafe extern "C" fn(i64) -> *mut std::ffi::c_char) -> Result<String> {
        // SAFETY: our pool's handle; the result is ours to free.
        let result = unsafe { ffi::take_string(get(self.handle)) };
        ffi::checked(result, "reading the pool")
    }

    /// The pool's name, from its definition.
    pub fn name(&self) -> Result<String> {
        self.name_from(sys::httpcloak_pool_name)
    }

    /// How many presets the pool holds.
    pub fn len(&self) -> usize {
        // SAFETY: plain call with our handle.
        usize::try_from(unsafe { sys::httpcloak_pool_size(self.handle) }).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// A preset chosen by the pool's own strategy, random or round robin.
    pub fn pick(&self) -> Result<String> {
        self.name_from(sys::httpcloak_pool_pick)
    }

    /// A preset chosen at random.
    pub fn random(&self) -> Result<String> {
        self.name_from(sys::httpcloak_pool_random)
    }

    /// The next preset in round-robin order, whatever the pool's strategy.
    pub fn next_preset(&self) -> Result<String> {
        self.name_from(sys::httpcloak_pool_next)
    }

    /// The preset at `index`, in definition order.
    pub fn get(&self, index: usize) -> Option<String> {
        let index = i64::try_from(index).ok()?;
        // SAFETY: plain call; the library checks the index, and the result is
        // ours to free.
        let result = unsafe { ffi::take_string(sys::httpcloak_pool_get(self.handle, index)) };
        ffi::checked(result, "reading the pool").ok()
    }

    /// Every preset in the pool, in definition order.
    pub fn presets(&self) -> Vec<String> {
        (0..self.len()).map_while(|i| self.get(i)).collect()
    }
}

impl Drop for PresetPool {
    fn drop(&mut self) {
        // SAFETY: our pool's handle, freed once, here.
        unsafe { sys::httpcloak_pool_free(self.handle) }
    }
}

impl fmt::Debug for PresetPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PresetPool").field("name", &self.name().ok()).field("len", &self.len()).finish()
    }
}
