#!/usr/bin/env python3
"""Test available_presets() returns dict with protocol support info."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'bindings', 'python'))
os.environ.setdefault("HTTPCLOAK_LIB_PATH",
    os.path.join(os.path.dirname(__file__), '..', '..', 'bindings', 'clib', 'libhttpcloak-linux-amd64.so'))

import httpcloak

EXPECTED_H3 = {
    "chrome-143", "chrome-143-windows", "chrome-143-linux", "chrome-143-macos",
    "chrome-144", "chrome-144-windows", "chrome-144-linux", "chrome-144-macos",
    "chrome-145", "chrome-145-windows", "chrome-145-linux", "chrome-145-macos",
    "safari-18", "chrome-143-ios", "chrome-144-ios", "chrome-145-ios",
    "safari-18-ios", "chrome-143-android", "chrome-144-android", "chrome-145-android",
}

EXPECTED_NO_H3 = {"chrome-133", "chrome-141", "firefox-133", "safari-17-ios"}

ALL_EXPECTED = EXPECTED_H3 | EXPECTED_NO_H3

def main():
    print("=" * 60)
    print("Test: available_presets() dict format")
    print("=" * 60)
    passed = 0
    failed = 0

    presets = httpcloak.available_presets()

    # 1. Return type is dict
    is_dict = isinstance(presets, dict)
    status = "PASS" if is_dict else "FAIL"
    print(f"  [{status}] Return type is dict: {type(presets).__name__}")
    if is_dict: passed += 1
    else: failed += 1

    # 2. Has expected count
    count_ok = len(presets) == len(ALL_EXPECTED)
    status = "PASS" if count_ok else "FAIL"
    print(f"  [{status}] Preset count: {len(presets)} (expected {len(ALL_EXPECTED)})")
    if count_ok: passed += 1
    else: failed += 1

    # 3. All expected presets present
    missing = ALL_EXPECTED - set(presets.keys())
    extra = set(presets.keys()) - ALL_EXPECTED
    all_present = len(missing) == 0 and len(extra) == 0
    status = "PASS" if all_present else "FAIL"
    print(f"  [{status}] All expected presets present")
    if missing:
        print(f"         Missing: {missing}")
    if extra:
        print(f"         Extra: {extra}")
    if all_present: passed += 1
    else: failed += 1

    # 4. Each preset has protocols list
    all_have_protocols = True
    for name, info in presets.items():
        if not isinstance(info, dict) or "protocols" not in info:
            print(f"  [FAIL] {name}: missing 'protocols' key, got {info}")
            all_have_protocols = False
            break
        if not isinstance(info["protocols"], list):
            print(f"  [FAIL] {name}: protocols is not a list, got {type(info['protocols']).__name__}")
            all_have_protocols = False
            break
    status = "PASS" if all_have_protocols else "FAIL"
    print(f"  [{status}] All presets have 'protocols' list")
    if all_have_protocols: passed += 1
    else: failed += 1

    # 5. All presets have h1 and h2
    all_have_h1h2 = True
    for name, info in presets.items():
        protos = info.get("protocols", [])
        if "h1" not in protos or "h2" not in protos:
            print(f"  [FAIL] {name}: missing h1/h2, has {protos}")
            all_have_h1h2 = False
    status = "PASS" if all_have_h1h2 else "FAIL"
    print(f"  [{status}] All presets have h1 and h2")
    if all_have_h1h2: passed += 1
    else: failed += 1

    # 6. H3-capable presets have h3
    h3_correct = True
    for name in EXPECTED_H3:
        if name in presets:
            protos = presets[name].get("protocols", [])
            if "h3" not in protos:
                print(f"  [FAIL] {name}: should have h3 but has {protos}")
                h3_correct = False
    status = "PASS" if h3_correct else "FAIL"
    print(f"  [{status}] H3 presets have h3 protocol")
    if h3_correct: passed += 1
    else: failed += 1

    # 7. Non-H3 presets don't have h3
    no_h3_correct = True
    for name in EXPECTED_NO_H3:
        if name in presets:
            protos = presets[name].get("protocols", [])
            if "h3" in protos:
                print(f"  [FAIL] {name}: should NOT have h3 but has {protos}")
                no_h3_correct = False
    status = "PASS" if no_h3_correct else "FAIL"
    print(f"  [{status}] Non-H3 presets don't have h3")
    if no_h3_correct: passed += 1
    else: failed += 1

    # Summary
    print()
    print("=" * 60)
    total = passed + failed
    print(f"Result: {passed}/{total} checks passed")
    if failed > 0:
        print("FAILED")
        return 1
    else:
        print("ALL PASSED")
        return 0

if __name__ == "__main__":
    sys.exit(main())
