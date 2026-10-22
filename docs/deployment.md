# AI-UBA: Linux-da deploy və dashboard

AI-UBA API və dashboard **tək proses, tək port** üzərində işləyir (FastAPI + uvicorn). UI üçün
ayrıca web server, Node.js və ya internet (CDN) tələb olunmur.

| | |
|---|---|
| Defolt ünvan | `http://127.0.0.1:8088` |
| Port/host dəyişmək | `AIUBA_API__PORT`, `AIUBA_API__HOST` |
| Giriş nöqtəsi | `python main.py` |
| Wazuh Indexer | `AIUBA_WAZUH_INDEXER__*` (host, port, username, password, verify_ssl) |

## 1. Sürətli lokal işə salma (inkişaf)

```bash
cd UserBehaviorAnalysis
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

export AIUBA_WAZUH_INDEXER__PASSWORD='<indexer admin parolu>'
python main.py
# -> http://127.0.0.1:8088
```

Port tutulubsa: `ss -ltnp | grep 8088`, sonra `AIUBA_API__PORT=8090 python main.py`.

## 2. systemd ilə deploy (tövsiyə olunan)

```bash
sudo ./deploy/install.sh
sudo nano /etc/aiuba/aiuba.env      # parolları təyin edin
sudo systemctl start aiuba
sudo systemctl status aiuba
journalctl -u aiuba -f              # canlı loglar
```

`install.sh` nə edir:

- `aiuba` adlı sistem istifadəçisi yaradır (login shell-i yoxdur)
- kodu `/opt/aiuba`-ya kopyalayır (kod **root**-a məxsusdur, servis ona yaza bilmir), ayrıca venv qurur
- yalnız `/opt/aiuba/data` və `/opt/aiuba/logs` servis üçün yazıla bilən qalır
- parolları `/etc/aiuba/aiuba.env` faylında saxlayır (`chmod 600`, sahibi root); repo-ya düşmür
- `aiuba.service` unit-ini quraşdırıb `enable` edir (server yenidən başlayanda avtomatik qalxır)

**Yeniləmə:** repo-da `git pull`, sonra yenidən `sudo ./deploy/install.sh`. Mövcud `aiuba.env`
toxunulmaz qalır, servis avtomatik restart olunur.

## 3. Dashboard-a necə çatmaq

Defolt olaraq servis **yalnız `127.0.0.1`**-də dinləyir, yəni şəbəkədən görünmür. Üç variant:

**a) SSH tunnel (ən sadə və təhlükəsiz).** Öz kompüterinizdən:

```bash
ssh -L 8088:127.0.0.1:8088 socadmin@<server-ip>
# sonra brauzerdə: http://127.0.0.1:8088
```

**b) Reverse proxy ilə TLS (komanda üçün).** `aiuba.env`-də host `127.0.0.1` qalır, nginx 443-də TLS verir:

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

**c) Birbaşa şəbəkəyə açmaq.** `AIUBA_API__HOST=0.0.0.0` və **mütləq** `AIUBA_API__BASIC_PASSWORD` təyin edin,
firewall-da yalnız lazım olan IP-yə icazə verin (`sudo ufw allow from <ip> to any port 8088 proto tcp`).
Basic Auth şifrələmir; açıq HTTP üzərindən istifadə etməyin, (b) variantını seçin.

## 4. Təhlükəsizlik qeydləri

- Dashboard log məzmununu göstərir (istifadəçi adı, komanda sətri, fayl yolu), bu da hücumçunun nəzarətində ola bilər.
  UI buna görə yalnız `textContent` ilə yazır, inline skript/stil yoxdur və CSP `script-src 'self'` tətbiq olunur. UI-ya kod əlavə edərkən `innerHTML` istifadə etməyin.
- `/healthz` autentifikasiyasızdır və yalnız `{"status":"ok"}` qaytarır (monitorinq üçün). Qalan hər şey Basic Auth arxasındadır (parol təyin olunubsa).
- Swagger/OpenAPI səhifələri söndürülüb.
- Indexer parolu və dashboard parolu yalnız `aiuba.env`-də saxlanılmalıdır, `config.yaml`-a yazmayın.
- `wazuh_indexer.verify_ssl=false` yalnız self-signed sertifikatlı test mühiti üçündür. Production-da sertifikatı doğrulayın.

## 5. Problemlərin həlli

| Dashboard-da mesaj / simptom | Səbəb və həll |
|---|---|
| `Indexer-ə qoşulmaq olmadı` | Wazuh Docker işləmirmi (`docker ps`)? `9200:9200` port mapping var? `curl -k -u admin:<parol> https://127.0.0.1:9200` |
| `Indexer autentifikasiya xətası` | `AIUBA_WAZUH_INDEXER__USERNAME/PASSWORD` səhvdir |
| `SSL xətası` | `AIUBA_WAZUH_INDEXER__VERIFY_SSL=false` (test) və ya düzgün CA |
| Brauzer 401 verir | `AIUBA_API__BASIC_USER/PASSWORD` ilə daxil olun |
| Event sayı 0 | Seçilmiş pəncərədə uyğun event yoxdur: pəncərəni böyüdün, agentdə aktivlik yaradın |
| Sarı xəbərdarlıq: "yalnız ən yeni N event təhlil olundu" | Pəncərədə limitdən çox event var; pəncərəni daraldın və ya `AIUBA_API__MAX_EVENTS_PER_SOURCE` artırın (maks. 10000) |
| Servis qalxmır | `journalctl -u aiuba -n 50 --no-pager`; port konflikti: `ss -ltnp \| grep 8088` |

## 6. Testlər

```bash
pip install -r requirements-dev.txt
pytest
```
