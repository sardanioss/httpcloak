/**
 * HTTPCloak Node.js Client - ESM Module
 *
 * A fetch/axios-compatible HTTP client with browser fingerprint emulation.
 * Provides TLS fingerprinting for HTTP requests.
 */

import { createRequire } from "module";
const require = createRequire(import.meta.url);

// Import the CommonJS module
const cjs = require("./index.js");

// Re-export all named exports
// Classes
export const Session = cjs.Session;
export const LocalProxy = cjs.LocalProxy;
export const Response = cjs.Response;
export const FastResponse = cjs.FastResponse;
export const StreamResponse = cjs.StreamResponse;
export const Cookie = cjs.Cookie;
export const RedirectInfo = cjs.RedirectInfo;
export const HTTPCloakError = cjs.HTTPCloakError;
export const SessionCacheBackend = cjs.SessionCacheBackend;
export const PresetPool = cjs.PresetPool;

// Presets
export const Preset = cjs.Preset;

// Custom preset loading
export const loadPreset = cjs.loadPreset;
export const loadPresetFromJSON = cjs.loadPresetFromJSON;
export const unregisterPreset = cjs.unregisterPreset;
export const describePreset = cjs.describePreset;

// Configuration
export const configure = cjs.configure;
export const configureSessionCache = cjs.configureSessionCache;
export const clearSessionCache = cjs.clearSessionCache;

// Module-level functions
export const get = cjs.get;
export const post = cjs.post;
export const put = cjs.put;
export const patch = cjs.patch;
export const head = cjs.head;
export const options = cjs.options;
export const request = cjs.request;

// Utility
export const version = cjs.version;
export const trimMemory = cjs.trimMemory;
export const availablePresets = cjs.availablePresets;

// DNS configuration
export const setEchDnsServers = cjs.setEchDnsServers;
export const getEchDnsServers = cjs.getEchDnsServers;

// 'delete' is a reserved word in ESM, so we export it specially
const del = cjs.delete;
export { del as delete };

// Default export (the entire module)
export default cjs;
