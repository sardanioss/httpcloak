import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

const sidebars: SidebarsConfig = {
  docsSidebar: [
    'index',
    'installation',
    {
      type: 'category',
      label: 'Getting Started',
      link: { type: 'doc', id: 'getting-started/index' },
      items: [
        'getting-started/first-request',
        'getting-started/presets-explained',
        'getting-started/common-options',
      ],
    },
    {
      type: 'category',
      label: 'Proxies',
      link: { type: 'doc', id: 'proxies/index' },
      items: [
        'proxies/overview',
        'proxies/http-connect',
        'proxies/socks5',
        'proxies/socks5-udp',
        'proxies/masque',
        'proxies/source-address-binding',
      ],
    },
    {
      type: 'category',
      label: 'Cookies & State',
      link: { type: 'doc', id: 'cookies-and-state/index' },
      items: [
        'cookies-and-state/cookie-jar',
        'cookies-and-state/disabling-cookie-jar',
        'cookies-and-state/per-request-cookies',
        'cookies-and-state/domain-and-path-matching',
      ],
    },
    {
      type: 'category',
      label: 'Fingerprinting',
      link: { type: 'doc', id: 'fingerprinting/index' },
      items: [
        'fingerprinting/what-is-tls-fingerprinting',
        'fingerprinting/presets',
        'fingerprinting/json-preset-builder',
        'fingerprinting/custom-ja3',
        'fingerprinting/akamai-shorthand',
        'fingerprinting/per-resource-priority',
      ],
    },
    {
      type: 'category',
      label: 'Connection Lifecycle',
      link: { type: 'doc', id: 'connection-lifecycle/index' },
      items: [
        'connection-lifecycle/refresh',
        'connection-lifecycle/warmup',
        'connection-lifecycle/protocol-switching',
        'connection-lifecycle/session-save-restore',
      ],
    },
    {
      type: 'category',
      label: 'HTTP Protocols',
      link: { type: 'doc', id: 'http-protocols/index' },
      items: [
        'http-protocols/http1',
        'http-protocols/http2',
        'http-protocols/http3-quic',
        'http-protocols/auto-negotiation',
      ],
    },
    {
      type: 'category',
      label: 'Advanced TLS',
      link: { type: 'doc', id: 'advanced-tls/index' },
      items: [
        'advanced-tls/ech',
        'advanced-tls/speculative-tls',
        'advanced-tls/tls-keylog',
        'advanced-tls/domain-fronting',
      ],
    },
    {
      type: 'category',
      label: 'Requests & Responses',
      link: { type: 'doc', id: 'requests-and-responses/index' },
      items: [
        'requests-and-responses/headers',
        'requests-and-responses/json-bodies',
        'requests-and-responses/form-data-and-multipart',
        'requests-and-responses/streaming-responses',
        'requests-and-responses/error-handling',
      ],
    },
    {
      type: 'category',
      label: 'Bindings',
      link: { type: 'doc', id: 'bindings/index' },
      items: [
        'bindings/go',
        'bindings/python',
        'bindings/nodejs',
        'bindings/dotnet',
      ],
    },
    {
      type: 'category',
      label: 'Reference',
      link: { type: 'doc', id: 'reference/index' },
      items: [
        'reference/options',
        'reference/presets',
        'reference/json-preset-spec',
        'reference/architecture',
      ],
    },
    {
      type: 'category',
      label: 'Recipes',
      link: { type: 'doc', id: 'recipes/index' },
      items: [
        'recipes/multi-proxy-rotation-with-state',
        'recipes/build-custom-chrome-from-tls-peet',
        'recipes/long-running-scraper-patterns',
        'recipes/debug-with-wireshark',
      ],
    },
    'changelog',
  ],
};

export default sidebars;
