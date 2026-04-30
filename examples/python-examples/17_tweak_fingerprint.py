#!/usr/bin/env python3
"""
Tweak Specific Fingerprint Values

For most users, picking a built-in preset (chrome-latest, firefox-148, etc.)
is enough — the wire bytes already match real browsers. This example is for
power users who want to tweak ONE OR TWO specific fingerprint values while
inheriting everything else from a built-in preset.

The recipe:
    1. describe_preset(name)        → JSON of all fingerprint fields
    2. edit the fields you want     → standard JSON dict mutation
    3. load_preset_from_json(...)   → registers under a new name
    4. Session(preset="new-name")   → uses your customized version

Why this works for any fingerprint field:
- describe_preset() emits ALL effective values (including inherited
  defaults like the per-resource-type priority table). Whatever you see
  in the output is editable.
- The mutated JSON round-trips byte-equal: same fingerprint mechanics,
  just the values you changed.
- Composes naturally: priority + headers + JA3 + akamai + settings can
  all be tweaked in one pass.

What this example covers:
    Recipe 1 — bump the H2 stream priority for image requests
    Recipe 2 — replace the HPACK header order
    Recipe 3 — start from a tls.peet.ws capture (JA3 + akamai)
    Recipe 4 — clean up custom presets when done

Requirements:
    pip install httpcloak

Run:
    python 17_tweak_fingerprint.py
"""

import json

import httpcloak


# ============================================================
# Recipe 1: Bump image-request priority urgency
# ============================================================
# Real Chrome 147 emits weight=183 (urgency=2) for <img> requests. Suppose
# you're impersonating a custom Chromium build that bumps images to
# weight=220 (urgency=1). Tweak just the "image" entry — every other
# fingerprint field stays inherited from chrome-147-windows.

print("=" * 60)
print("Recipe 1: Bump image priority from u=2 (183) to u=1 (220)")
print("-" * 60)

p = json.loads(httpcloak.describe_preset("chrome-147-windows"))
p["preset"]["name"] = "chrome-147-img-bumped"
p["preset"]["http2"]["priority_table"]["image"] = {
    "urgency": 1,
    "incremental": True,
    "emit_header": True,
}
httpcloak.load_preset_from_json(json.dumps(p))

with httpcloak.Session(preset="chrome-147-img-bumped") as session:
    # Images now emit weight=220 instead of weight=183 on the H2 frame.
    response = session.get(
        "https://tls.peet.ws/api/all",
        headers={"Sec-Fetch-Dest": "image"},
    )
    sent = response.json().get("http2", {}).get("sent_frames", [])
    headers_frame = next((f for f in sent if f.get("frame_type") == "HEADERS"), None)
    if headers_frame:
        priority = headers_frame.get("priority", {})
        print(f"H2 frame priority: weight={priority.get('weight')} "
              f"exclusive={priority.get('exclusive')}")
        print("Expected weight=220 (u=1) instead of 183 (u=2)")


# ============================================================
# Recipe 2: Customize HPACK header order
# ============================================================
# Insert an extra header into the canonical order so it gets emitted
# in the right wire position. Same describe-edit-load loop.

print("\n" + "=" * 60)
print("Recipe 2: Append a header to the HPACK header order")
print("-" * 60)

p = json.loads(httpcloak.describe_preset("chrome-147-windows"))
p["preset"]["name"] = "chrome-147-with-tracking-header"
# Insert "x-tracking-id" right before "priority" — the last entry.
order = p["preset"]["http2"]["hpack_header_order"]
order.insert(order.index("priority"), "x-tracking-id")
httpcloak.load_preset_from_json(json.dumps(p))

print(f"New header order: {order}")


# ============================================================
# Recipe 3: Start from a tls.peet.ws capture
# ============================================================
# Visit https://tls.peet.ws/api/all in the browser you want to mimic.
# Copy:
#   - data["tls"]["ja3"]                  → preset's tls.ja3
#   - data["http2"]["akamai_fingerprint"] → preset's http2.akamai
# The H2 priority frame in sent_frames[0].priority is the navigation
# priority (dest=document) only. For per-dest priority across the full
# resource set, run the H2 capture-server tool — see the local-server
# documentation in internal_docs.

print("\n" + "=" * 60)
print("Recipe 3: Build a preset from a peet.ws capture")
print("-" * 60)

# Replace these with actual values from your peet.ws visit.
PEET_JA3 = (
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172"
    "-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-65037,29-23-24,0"
)
PEET_AKAMAI = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"

p = json.loads(httpcloak.describe_preset("chrome-147-windows"))
p["preset"]["name"] = "from-peet-capture"
p["preset"]["tls"] = {"ja3": PEET_JA3}
# Note: http2.akamai overrides settings/window/single-weight/pseudo-order.
# The priority_table (per-dest) is independent — leave it inherited or
# replace it from a multi-dest capture.
p["preset"]["http2"]["akamai"] = PEET_AKAMAI
httpcloak.load_preset_from_json(json.dumps(p))

with httpcloak.Session(preset="from-peet-capture") as session:
    response = session.get("https://tls.peet.ws/api/tls")
    data = response.json()
    print(f"JA3 hash:  {data.get('tls', {}).get('ja3_hash', 'N/A')}")
    print(f"JA3 sent matches PEET_JA3: "
          f"{data.get('tls', {}).get('ja3', '') == PEET_JA3}")


# ============================================================
# Recipe 4: Clean up custom presets when done
# ============================================================
# Custom presets stay registered in-process until unregister_preset() is
# called. Long-running processes that build many presets dynamically should
# clean up to avoid memory growth.

print("\n" + "=" * 60)
print("Recipe 4: Unregister custom presets")
print("-" * 60)

for name in ("chrome-147-img-bumped", "chrome-147-with-tracking-header", "from-peet-capture"):
    httpcloak.unregister_preset(name)
    print(f"Unregistered: {name}")


# ============================================================
# Summary
# ============================================================
print("\n" + "=" * 60)
print("Summary")
print("=" * 60)
print("""
The describe → edit → load_preset_from_json workflow lets you tweak ANY
fingerprint value while inheriting the rest. Common edit points:

    p["preset"]["http2"]["priority_table"][dest]   per-resource priorities
    p["preset"]["http2"]["hpack_header_order"]     HPACK encoding order
    p["preset"]["http2"]["settings_order"]         SETTINGS frame ID order
    p["preset"]["http2"]["pseudo_order"]           HTTP/2 pseudo-headers
    p["preset"]["http2"]["akamai"]                 single-string override
    p["preset"]["http3"][...]                      HTTP/3 / QUIC params
    p["preset"]["tls"]["ja3"]                      JA3 string
    p["preset"]["tcp"][...]                        TCP/IP fingerprint
    p["preset"]["headers"]["values"]               static header values
    p["preset"]["headers"]["order"]                request header order

Print describe_preset(name) once to see the full editable surface.
""")
