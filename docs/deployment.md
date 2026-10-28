# UBA Linux deploymen and dashboard

UBA API and dashboard runs on **one process, one port** (FastAPI + uvicorn).

| | |
|---|---|
| Default port | `http://127.0.0.1:8088` |
| Port/host changing | `UBA_API__PORT`, `UBA_API__HOST` |
| Entry point | `python main.py` |
| Wazuh Indexer | `UBA_WAZUH_INDEXER__*` (host, port, username, password, verify_ssl) |

## 1. Fast local running

```bash
cd UserBehaviorAnalysis
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

export UBA_WAZUH_INDEXER__PASSWORD='<indexer admin password>'
python main.py
# -> http://127.0.0.1:8088
```

If port is busy: `ss -ltnp | grep 8088`, sonra `UBA_API__PORT=8090 python main.py`.

## 2. Deployment with systemd (recommended)

```bash
sudo ./deploy/install.sh
sudo nano /etc/uba/uba.env      # determine passwords
sudo systemctl start uba
sudo systemctl status uba
journalctl -u uba -f              # live logs
```

What does `install.sh`:

- `uba` adlı sistem istifadəçisi yaradır (nothing any login shell)
- copied password to `/opt/uba` (password belongs to the **root**, so service cannot write them), creates different venv
- only `/opt/uba/data` and `/opt/uba/logs` staying write only for service
- passwords stored in `/etc/uba/uba.env` file (`chmod 600`, owner is root); not seen in repo
- configured unit `uba.service` and change to`enable` (service is going up every running of server)

**Update:** In the repo `git pull`, then again `sudo ./deploy/install.sh`. Existing `uba.env`
staying untouchable, service will restart automatically.

## 3. How reach Dashboard

By default **only `127.0.0.1`** listened, so not seen by network. Three type:

**a) SSH tunnel (simple and secure).** in the local machine:

```bash
ssh -L 8088:127.0.0.1:8088 socadmin@<server-ip>
# then from browser: http://127.0.0.1:8088
```

**b) Reverse proxy with TLS (for command).** host is `uba.env` staying `127.0.0.1`, in the nginx 443 gives TLS:

```nginx
server {
    listen 443 ssl;
    server_name uba.example.local;
    ssl_certificate     /etc/ssl/uba.crt;
    ssl_certificate_key /etc/ssl/uba.key;
    location / {
        proxy_pass http://127.0.0.1:8088;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**c) Directly open to network.** `UBA_API__HOST=0.0.0.0` və **important** `UBA_API__BASIC_PASSWORD` determine,
please give permission only necessary IP address (`sudo ufw allow from <ip> to any port 8088 proto tcp`).
Basic Auth not encrypted; don't use from open HTTP, use (b).

## 4. Security notes

- Dashboard screening content of log (username, command prompt, file path), it is may undercontrol to attacker.
  Therefore UI only write with `textContent`, there are nothing inline script/style and CSP `script-src 'self'`. When adding script to UI don't use `innerHTML`.
- `/healthz` is unauthenticated and only returns `{"status":"ok"}` (for monitoring). All of the others background of Basic Auth (if it has been assinged).
- Swagger/OpenAPI pages are off.
- The password of indexer stored only in `uba.env`, do not write to the `config.yaml`file.
- Certificate of self-signed `wazuh_indexer.verify_ssl=false` is only for test env. Please confirm certificate in the production.

## 5. Problem solving

| Message on the Dashboard | Reason and solving |
|---|---|
| `Indexer not reachable` | Is Wazuh Docker not working?  (`docker ps`)? `9200:9200` is port mapping enable? `curl -k -u admin:<parol> https://127.0.0.1:9200` |
| `Indexer authentication error` | `UBA_WAZUH_INDEXER__USERNAME/PASSWORD` is wrong |
| `SSL xətası` | `UBA_WAZUH_INDEXER__VERIFY_SSL=false` (test) or true CA |
| Browser 401 error | Log in `AIUBA_API__BASIC_USER/PASSWORD` |
| Event count 0 | There are not any suitable in the selected window: enlarge the window, create active trigger in the agent |
| Yellow warning: "only the newest N events were analyzed" | There are less event than limit; narrow the window or `UBA_API__MAX_EVENTS_PER_SOURCE` enlarge (max. 10000) |
| Service is not reachable| `journalctl -u uba -n 50 --no-pager`; port conflict: `ss -ltnp \| grep 8088` |

## 6. Tests

```bash
pip install -r requirements-dev.txt
pytest
```
