---
title: Installation
sidebar_position: 2
---

# Installation

Pick your binding. Once it is installed, head to [First Request](./getting-started/first-request) to send something.

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```sh
go get github.com/sardanioss/httpcloak
```

Requires Go 1.26+ (matches the version in the module's `go.mod`). The Go core has no cgo dependency.

</TabItem>
<TabItem value="python" label="Python">

```sh
pip install httpcloak
```

Wheels ship for `linux-x64`, `linux-arm64`, `darwin-x64`, `darwin-arm64`, `win32-x64`. Python 3.9+.

</TabItem>
<TabItem value="node" label="Node.js">

```sh
npm install httpcloak
```

Node 18+. Optional native deps auto-resolve to your platform; ESM and CJS both supported.

</TabItem>
<TabItem value="dotnet" label=".NET">

```sh
dotnet add package HttpCloak
```

.NET 8+ on the same five platforms as Python. Uses P/Invoke to call into the shared library.

</TabItem>
</Tabs>

## Pointing a process at a specific build

Every binding except Go honours `HTTPCLOAK_LIB_PATH`. Set it to the shared
library file, or to a directory holding it under the usual name, and that
process loads that build instead of the one shipped with the package.

```sh
HTTPCLOAK_LIB_PATH=/opt/httpcloak/engines/current ./my-bot
```

It exists for a fleet that deploys many processes into one shared directory.
The normal search looks next to the installed package, so a shared directory
means a single build for everyone and no way to stage a rollout across it.
The variable gives back the per-process choice without splitting the fleet
into separate folders.

Two things to know. A value that points at neither a file nor a directory
containing one is ignored rather than fatal, so a stale variable falls back to
the normal search instead of taking the process down. And the variable only
wins over the packaged library, so on a machine where some processes set it and
others do not, the ones that do not keep using whatever the install directory
holds.

The shared library is backward compatible: a binding built against an older
release runs on a newer library, which is what makes swapping the file a safe
way to pick up new fingerprints without rebuilding. The reverse is not true, so
do not point a newer binding at an older library.

Next: [send your first request](./getting-started/first-request).
