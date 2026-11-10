//! Names of the built-in browser presets, for
//! [`SessionBuilder::preset`](crate::SessionBuilder::preset).
//!
//! The `*_LATEST` names follow the newest version of each browser as the
//! library updates; a versioned name stays the same fingerprint for good. The
//! library resolves a name without a platform (`chrome-155`) to one for the
//! platform it runs on. [`available_presets`](crate::available_presets) lists
//! every name the library knows, these and the older spellings it keeps for
//! compatibility.
//!
//! The constants match the Python, Node.js and .NET bindings' by name, which a
//! test in the Go repository holds them to.

// Chrome latest (auto-resolves to newest shipped Chrome)
pub const CHROME_LATEST: &str = "chrome-latest";
pub const CHROME_LATEST_WINDOWS: &str = "chrome-latest-windows";
pub const CHROME_LATEST_LINUX: &str = "chrome-latest-linux";
pub const CHROME_LATEST_MACOS: &str = "chrome-latest-macos";
pub const CHROME_LATEST_IOS: &str = "chrome-latest-ios";
pub const CHROME_LATEST_ANDROID: &str = "chrome-latest-android";

// Chrome 153 (headers-only over 152; no iOS preset until one is captured)
pub const CHROME_153: &str = "chrome-153";
pub const CHROME_153_WINDOWS: &str = "chrome-153-windows";
pub const CHROME_153_LINUX: &str = "chrome-153-linux";
pub const CHROME_153_MACOS: &str = "chrome-153-macos";
pub const CHROME_153_ANDROID: &str = "chrome-153-android";

// Chrome 154 (headers-only over 153)
pub const CHROME_154: &str = "chrome-154";
pub const CHROME_154_WINDOWS: &str = "chrome-154-windows";
pub const CHROME_154_LINUX: &str = "chrome-154-linux";
pub const CHROME_154_MACOS: &str = "chrome-154-macos";
pub const CHROME_154_ANDROID: &str = "chrome-154-android";

// Chrome 155 (desktop and Android add image/jxl to Accept; TLS unchanged; iOS captured)
pub const CHROME_155: &str = "chrome-155";
pub const CHROME_155_WINDOWS: &str = "chrome-155-windows";
pub const CHROME_155_LINUX: &str = "chrome-155-linux";
pub const CHROME_155_MACOS: &str = "chrome-155-macos";
pub const CHROME_155_IOS: &str = "chrome-155-ios";
pub const CHROME_155_ANDROID: &str = "chrome-155-android";

// Chrome 152 (trust anchors, plus a greased signature algorithm on TCP)
pub const CHROME_152: &str = "chrome-152";
pub const CHROME_152_WINDOWS: &str = "chrome-152-windows";
pub const CHROME_152_LINUX: &str = "chrome-152-linux";
pub const CHROME_152_MACOS: &str = "chrome-152-macos";
pub const CHROME_152_ANDROID: &str = "chrome-152-android";
pub const CHROME_152_IOS: &str = "chrome-152-ios";

// Chrome 151 (headers only over 150)
pub const CHROME_151: &str = "chrome-151";
pub const CHROME_151_WINDOWS: &str = "chrome-151-windows";
pub const CHROME_151_LINUX: &str = "chrome-151-linux";
pub const CHROME_151_MACOS: &str = "chrome-151-macos";
pub const CHROME_151_ANDROID: &str = "chrome-151-android";
pub const CHROME_151_IOS: &str = "chrome-151-ios";

pub const CHROME_150: &str = "chrome-150";
pub const CHROME_150_WINDOWS: &str = "chrome-150-windows";
pub const CHROME_150_LINUX: &str = "chrome-150-linux";
pub const CHROME_150_MACOS: &str = "chrome-150-macos";
pub const CHROME_150_ANDROID: &str = "chrome-150-android";
pub const CHROME_150_IOS: &str = "chrome-150-ios";

pub const FIREFOX_148_WINDOWS: &str = "firefox-148-windows";
pub const FIREFOX_148_LINUX: &str = "firefox-148-linux";
pub const FIREFOX_148_MACOS: &str = "firefox-148-macos";
pub const FIREFOX_133_WINDOWS: &str = "firefox-133-windows";
pub const FIREFOX_133_LINUX: &str = "firefox-133-linux";
pub const FIREFOX_133_MACOS: &str = "firefox-133-macos";
pub const FIREFOX_LATEST_WINDOWS: &str = "firefox-latest-windows";
pub const FIREFOX_LATEST_LINUX: &str = "firefox-latest-linux";
pub const FIREFOX_LATEST_MACOS: &str = "firefox-latest-macos";

pub const CHROME_149: &str = "chrome-149";
pub const CHROME_149_WINDOWS: &str = "chrome-149-windows";
pub const CHROME_149_LINUX: &str = "chrome-149-linux";
pub const CHROME_149_MACOS: &str = "chrome-149-macos";

// Chrome 148
pub const CHROME_148: &str = "chrome-148";
pub const CHROME_148_WINDOWS: &str = "chrome-148-windows";
pub const CHROME_148_LINUX: &str = "chrome-148-linux";
pub const CHROME_148_MACOS: &str = "chrome-148-macos";
pub const CHROME_148_IOS: &str = "chrome-148-ios";
pub const CHROME_148_ANDROID: &str = "chrome-148-android";

// Chrome 147
pub const CHROME_147: &str = "chrome-147";
pub const CHROME_147_WINDOWS: &str = "chrome-147-windows";
pub const CHROME_147_LINUX: &str = "chrome-147-linux";
pub const CHROME_147_MACOS: &str = "chrome-147-macos";
pub const CHROME_147_IOS: &str = "chrome-147-ios";
pub const CHROME_147_ANDROID: &str = "chrome-147-android";

// Chrome 146
pub const CHROME_146: &str = "chrome-146";
pub const CHROME_146_WINDOWS: &str = "chrome-146-windows";
pub const CHROME_146_LINUX: &str = "chrome-146-linux";
pub const CHROME_146_MACOS: &str = "chrome-146-macos";
pub const CHROME_146_IOS: &str = "chrome-146-ios";
pub const CHROME_146_ANDROID: &str = "chrome-146-android";

// Chrome 145
pub const CHROME_145: &str = "chrome-145";
pub const CHROME_145_WINDOWS: &str = "chrome-145-windows";
pub const CHROME_145_LINUX: &str = "chrome-145-linux";
pub const CHROME_145_MACOS: &str = "chrome-145-macos";
pub const CHROME_145_IOS: &str = "chrome-145-ios";
pub const CHROME_145_ANDROID: &str = "chrome-145-android";

// Chrome 144
pub const CHROME_144: &str = "chrome-144";
pub const CHROME_144_WINDOWS: &str = "chrome-144-windows";
pub const CHROME_144_LINUX: &str = "chrome-144-linux";
pub const CHROME_144_MACOS: &str = "chrome-144-macos";
pub const CHROME_144_IOS: &str = "chrome-144-ios";
pub const CHROME_144_ANDROID: &str = "chrome-144-android";

// Chrome 143
pub const CHROME_143: &str = "chrome-143";
pub const CHROME_143_WINDOWS: &str = "chrome-143-windows";
pub const CHROME_143_LINUX: &str = "chrome-143-linux";
pub const CHROME_143_MACOS: &str = "chrome-143-macos";
pub const CHROME_143_IOS: &str = "chrome-143-ios";
pub const CHROME_143_ANDROID: &str = "chrome-143-android";

// Older Chrome (H1/H2 only, no H3)
pub const CHROME_141: &str = "chrome-141";
pub const CHROME_133: &str = "chrome-133";

// Firefox
pub const FIREFOX_LATEST: &str = "firefox-latest";
pub const FIREFOX_148: &str = "firefox-148";
pub const FIREFOX_133: &str = "firefox-133";

// Safari (desktop and mobile)
pub const SAFARI_LATEST: &str = "safari-latest";
pub const SAFARI_18: &str = "safari-18";
pub const SAFARI_17_IOS: &str = "safari-17-ios";
pub const SAFARI_18_IOS: &str = "safari-18-ios";
pub const SAFARI_LATEST_IOS: &str = "safari-latest-ios";

// Backwards compatibility aliases (old naming convention used "ios-chrome" / "android-chrome" prefix)
pub const IOS_CHROME_143: &str = CHROME_143_IOS;
pub const IOS_CHROME_144: &str = CHROME_144_IOS;
pub const IOS_CHROME_145: &str = CHROME_145_IOS;
pub const IOS_CHROME_146: &str = CHROME_146_IOS;
pub const IOS_CHROME_147: &str = CHROME_147_IOS;
pub const IOS_CHROME_148: &str = CHROME_148_IOS;
pub const IOS_CHROME_LATEST: &str = CHROME_LATEST_IOS;
pub const ANDROID_CHROME_143: &str = CHROME_143_ANDROID;
pub const ANDROID_CHROME_144: &str = CHROME_144_ANDROID;
pub const ANDROID_CHROME_145: &str = CHROME_145_ANDROID;
pub const ANDROID_CHROME_146: &str = CHROME_146_ANDROID;
pub const ANDROID_CHROME_147: &str = CHROME_147_ANDROID;
pub const ANDROID_CHROME_148: &str = CHROME_148_ANDROID;
pub const ANDROID_CHROME_LATEST: &str = CHROME_LATEST_ANDROID;
pub const IOS_SAFARI_17: &str = SAFARI_17_IOS;
pub const IOS_SAFARI_18: &str = SAFARI_18_IOS;
pub const IOS_SAFARI_LATEST: &str = SAFARI_LATEST_IOS;

/// Every preset name above, each once.
pub const ALL: &[&str] = &[
    CHROME_LATEST,
    CHROME_LATEST_WINDOWS,
    CHROME_LATEST_LINUX,
    CHROME_LATEST_MACOS,
    CHROME_LATEST_IOS,
    CHROME_LATEST_ANDROID,
    CHROME_153,
    CHROME_153_WINDOWS,
    CHROME_153_LINUX,
    CHROME_153_MACOS,
    CHROME_153_ANDROID,
    CHROME_154,
    CHROME_154_WINDOWS,
    CHROME_154_LINUX,
    CHROME_154_MACOS,
    CHROME_154_ANDROID,
    CHROME_155,
    CHROME_155_WINDOWS,
    CHROME_155_LINUX,
    CHROME_155_MACOS,
    CHROME_155_IOS,
    CHROME_155_ANDROID,
    CHROME_152,
    CHROME_152_WINDOWS,
    CHROME_152_LINUX,
    CHROME_152_MACOS,
    CHROME_152_ANDROID,
    CHROME_152_IOS,
    CHROME_151,
    CHROME_151_WINDOWS,
    CHROME_151_LINUX,
    CHROME_151_MACOS,
    CHROME_151_ANDROID,
    CHROME_151_IOS,
    CHROME_150,
    CHROME_150_WINDOWS,
    CHROME_150_LINUX,
    CHROME_150_MACOS,
    CHROME_150_ANDROID,
    CHROME_150_IOS,
    FIREFOX_148_WINDOWS,
    FIREFOX_148_LINUX,
    FIREFOX_148_MACOS,
    FIREFOX_133_WINDOWS,
    FIREFOX_133_LINUX,
    FIREFOX_133_MACOS,
    FIREFOX_LATEST_WINDOWS,
    FIREFOX_LATEST_LINUX,
    FIREFOX_LATEST_MACOS,
    CHROME_149,
    CHROME_149_WINDOWS,
    CHROME_149_LINUX,
    CHROME_149_MACOS,
    CHROME_148,
    CHROME_148_WINDOWS,
    CHROME_148_LINUX,
    CHROME_148_MACOS,
    CHROME_148_IOS,
    CHROME_148_ANDROID,
    CHROME_147,
    CHROME_147_WINDOWS,
    CHROME_147_LINUX,
    CHROME_147_MACOS,
    CHROME_147_IOS,
    CHROME_147_ANDROID,
    CHROME_146,
    CHROME_146_WINDOWS,
    CHROME_146_LINUX,
    CHROME_146_MACOS,
    CHROME_146_IOS,
    CHROME_146_ANDROID,
    CHROME_145,
    CHROME_145_WINDOWS,
    CHROME_145_LINUX,
    CHROME_145_MACOS,
    CHROME_145_IOS,
    CHROME_145_ANDROID,
    CHROME_144,
    CHROME_144_WINDOWS,
    CHROME_144_LINUX,
    CHROME_144_MACOS,
    CHROME_144_IOS,
    CHROME_144_ANDROID,
    CHROME_143,
    CHROME_143_WINDOWS,
    CHROME_143_LINUX,
    CHROME_143_MACOS,
    CHROME_143_IOS,
    CHROME_143_ANDROID,
    CHROME_141,
    CHROME_133,
    FIREFOX_LATEST,
    FIREFOX_148,
    FIREFOX_133,
    SAFARI_LATEST,
    SAFARI_18,
    SAFARI_17_IOS,
    SAFARI_18_IOS,
    SAFARI_LATEST_IOS,
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// ALL is a hand-kept list; it must name every preset above exactly once.
    #[test]
    fn all_lists_every_constant_once() {
        let source = include_str!("presets.rs");
        let mut values = HashSet::new();
        for line in source.lines() {
            if let Some(rest) = line.strip_prefix("pub const ") {
                if let Some((_, value)) = rest.split_once(": &str = \"") {
                    values.insert(value.trim_end_matches("\";").to_string());
                }
            }
        }
        let all: HashSet<String> = ALL.iter().map(|s| s.to_string()).collect();
        assert_eq!(all.len(), ALL.len(), "ALL names a preset twice");
        assert_eq!(all, values);
    }
}
