# vphone-burp-proxy

Turn a Burp Suite HTTP/HTTPS proxy on or off inside a vphone-cli iOS VM with one command.

The script edits the **guest's** network configuration over SSH. Your Mac's Wi-Fi, system proxy and routing stay as they are.

```text
$ ./vphone-burp-proxy.py on
proxy ON  192.168.64.1:8080  guest=192.168.64.5
  en0: HTTP 192.168.64.1:8080  HTTPS 192.168.64.1:8080
```

## Why

Proxying a VM's traffic usually means one of two things. You tap through Settings → Wi-Fi → Configure Proxy inside the guest every time, or you change the host's proxy and catch the Mac's own traffic too. vphone guests use a virtual **Ethernet** interface, which iOS Settings doesn't let you configure a proxy for. This script writes the proxy straight into the guest's `SystemConfiguration/preferences.plist` and reloads `configd`.

## Requirements

**Host (macOS, Apple Silicon)**

- Python 3.8+ (standard library only)
- `sshpass`: `brew install sshpass`
- Burp Suite (or any HTTP proxy) listening on the host

**Guest**

- A jailbroken vphone-cli VM with SSH as `root` on port **22222**
- Network in vphone NAT mode (host side is usually `bridge100`, `192.168.64.0/24`)

## Usage

```bash
chmod +x vphone-burp-proxy.py

./vphone-burp-proxy.py status   # show guest, gateway, Burp listener and proxy state
./vphone-burp-proxy.py on       # enable the HTTP + HTTPS proxy on every Ethernet service
./vphone-burp-proxy.py off      # restore the original config
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--guest <ip>` | auto-detect | Guest IPv4. Auto-detect reads `arp -a` for hosts on the vphone NAT subnet and keeps the first one that answers on SSH `:22222`. |
| `--host <ip>` | guest's default gateway | The proxy address the guest connects to. This is the NAT gateway (the Mac as the guest sees it), **not** your Wi-Fi IP. |
| `--port <n>` | `8080` | Burp listener port |

### Environment

| Variable | Default | Description |
|---|---|---|
| `VPHONE_SSH_PASS` | `alpine` | Root SSH password for the guest |

```bash
VPHONE_SSH_PASS='s3cret' ./vphone-burp-proxy.py on --guest 192.168.64.5 --port 8081
```

## Burp setup

1. **Proxy → Proxy settings → Proxy listeners**: bind to `192.168.64.1` (the NAT gateway) or to *All interfaces*, on the port you pass with `--port`.
2. Run `./vphone-burp-proxy.py on`. If nothing is listening on that address and port, the script prints a warning.
3. In the guest, open Safari at `http://burp` and install the CA certificate. Then turn on full trust under **Settings → General → About → Certificate Trust Settings**.
4. For the first test, leave intercept **off**. Load `http://example.com` in Safari and confirm the request shows up in HTTP history.

## How it works

1. **Find the guest.** The script lists the host's IPv4 addresses on `bridge*` / `vmenet*` interfaces, looks for ARP entries in the same `/24`, and probes each one on TCP `22222`.
2. **Find the proxy host.** It runs `netstat -rn` on the guest and takes the default gateway. If that fails, it falls back to the host's NAT address.
3. **Back up.** The first time you run `on`, it copies `/var/preferences/SystemConfiguration/preferences.plist` to `preferences.plist.bak`. Later runs keep that backup and don't overwrite it.
4. **Patch.** In every `NetworkServices` entry whose interface type is `Ethernet`, it sets:
   - `HTTPEnable` / `HTTPSEnable` = 1, pointing to `host:port`
   - `ExceptionsList` = `*.local`, `169.254/16` and the NAT `/24`, so local and host traffic skips the proxy
   - `SOCKSEnable` = 0
5. **Write and reload.** It writes the plist (binary format) to both `/var/preferences/...` and `/Library/Preferences/...`, then runs `killall configd` so the change applies right away.
6. **Off.** `off` restores the `.bak` if there is one. Otherwise it removes the HTTP/HTTPS/SOCKS proxy keys from the Ethernet services and keeps `FTPPassive` and the default exceptions.

`status` also lists any VPN profiles on the guest. They should stay disconnected, or they'll send traffic around the proxy.

## Notes and caveats

- **The change survives a reboot.** The config is written to disk. Run `off` before rebooting the guest if you don't want the proxy after restart.
- **The backup is taken once.** `.bak` is created on the first `on` and never refreshed. If you change the guest's network settings later, delete it first so the next `on` saves a fresh copy:
  ```bash
  ssh -p 22222 root@<guest> rm /var/preferences/SystemConfiguration/preferences.plist.bak
  ```
- **Mac IP changes don't matter.** The guest always reaches the host through the NAT gateway, so moving between Wi-Fi networks has no effect.
- **Only apps that honour the system proxy are captured.** Apps that ignore the system proxy or pin certificates need extra work, such as Frida or SSL-kill-switch-style bypasses.

## Security

This is a lab tool for a disposable research VM. Don't point it at a device you care about.

- SSH host key checking is **disabled** (`StrictHostKeyChecking=no`, `UserKnownHostsFile=/dev/null`).
- The password goes to `sshpass -p`, so other local users can see it in the process list.
- The default password is the well-known jailbreak default `alpine`. Change it on the guest and set `VPHONE_SSH_PASS`.

## Disclaimer

Use it only on devices and apps you own or are authorised to test.

## License

[MIT](LICENSE)
