# wg-dns-sync

Resolve DNS names and keep a WireGuard peer's `AllowedIPs` up to date.

## Commands

```bash
wg-dns-sync init                 # write a starter config (--interactive to be prompted)
wg-dns-sync resolve              # resolve DNS names and print the AllowedIPs set
wg-dns-sync render               # print the updated WireGuard config to stdout
wg-dns-sync diff                 # show the AllowedIPs changes without writing
wg-dns-sync update               # back up and rewrite the WireGuard config
wg-dns-sync validate             # check the app and WireGuard config
wg-dns-sync completion <shell>   # bash | zsh | fish | powershell
```

## Example

```bash
wg-dns-sync init
wg-dns-sync resolve --format wireguard
wg-dns-sync diff
wg-dns-sync update --dry-run
```

## Multiple peers

By default the single-peer fields (`wireguard.target_peer_public_key` plus
top-level `allowed_ips`) are used. To update several peers in one run, add a
`peers` list instead — each peer carries its own `static` CIDRs and `dns_names`:

```yaml
peers:
  - public_key: "KEY_A"
    static: ["10.0.0.0/8"]
    dns_names: ["a.example.com"]
  - public_key: "KEY_B"
    dns_names: ["b.example.com"]
```
