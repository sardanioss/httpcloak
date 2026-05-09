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

Requires Go 1.22+. The Go core has no cgo dependency.

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

Next: [send your first request](./getting-started/first-request).
