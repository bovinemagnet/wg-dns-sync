# wg-dns-sync

Resolve DNS names and keep a WireGuard peer's `AllowedIPs` up to date.

## Commands

```bash
wg-dns-sync init
wg-dns-sync resolve
wg-dns-sync render
wg-dns-sync update
wg-dns-sync validate
```

## Example

```bash
wg-dns-sync init
wg-dns-sync resolve --format wireguard
wg-dns-sync update --dry-run
```
