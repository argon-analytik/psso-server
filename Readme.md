# Argio Platform SSO Server (`psso-server`)

A lightweight Go service that implements Apple’s **Platform Single Sign‑On (PSSO)**
protocol and delegates all credential checks to your **Authentik** IdP
(`https://auth.argio.ch`).  
When combined with the *Argio SSO* macOS/iOS extension, it allows users to:

* log in **directly at the macOS login window** with their Authentik account  
* receive just‑in‑time local accounts & group mappings  
* unlock the Mac with the same cloud password (Touch ID / Face ID supported)  
* enjoy seamless SSO in Safari & native apps once the desktop appears

The server runs in Docker on your Synology NAS, listens on **:9100** inside the
compose network and is exposed publicly via a **Cloudflare Tunnel** as  
`https://psso.argio.ch`.

---

## Directory layout
```
.
├── cmd/
│   └── authentik/               # VerifyCredentials implementation
├── docker-compose.override.yml  # psso + cloudflared overlay
├── Dockerfile                   # builds the psso-server binary
├── .env.psso                    # example env‑file (edit & copy!)
└── README.md                    # this file
```

---

## Prerequisites

| Tool | Version | Comment |
|------|---------|---------|
| Docker / Docker Compose | 24.x | Already used by your Authentik stack |
| Cloudflare Tunnel | N/A | One active tunnel, credentials file on the NAS |
| Authentik | 2025.6.x | Container alias **`server`**, port **9000** |
| Go (local dev) | ≥ 1.22 (optional) | Only needed if you hack the code directly |

---

## 1  Quick Start (“I just want it running”)

```bash
# clone your fork on the NAS
git clone https://github.com/argon-analytik/psso-server-go.git
cd psso-server-go

# copy & edit env file
cp .env.psso .env      # adjust secrets only if they change

# launch only the PSSO overlay beside the existing Authentik stack
docker compose -f ../authentik/docker-compose.yml \
               -f docker-compose.override.yml      \
               --env-file .env up -d

# check health endpoint
curl -vk http://localhost:9100/healthz   # → "ok"
```

If you visit <https://psso.argio.ch/.well-known/jwks.json> in a browser and
receive JSON (no TLS warning), the tunnel is active.

---

## 2  Important ENV Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `PSSO_ADDRESS` | server listen address | `:9100` |
| `PSSO_ISSUER`  | must equal **Issuer** value in your macOS profile | `https://auth.argio.ch` |
| `PSSO_AUDIENCE`| audience claim in JWT | `macos` |
| `PSSO_DEVICE_REG_PATH` | device‑registration endpoint | `/v1/device/register` |
| `PSSO_USER_REG_PATH`   | user‑token endpoint | `/v1/user/token` |
| `PSSO_ADMIN_GROUPS`    | Authentik group → local macOS admin | `argon_admins` |
| `AUTHENTIK_TOKEN_ENDPOINT` | internal IdP token URL | `http://server:9000/application/o/token/` |
| `AUTHENTIK_CLIENT_ID` / `AUTHENTIK_CLIENT_SECRET` | confidential client for Password‑Grant | *(see .env.psso)* |

Advanced paths (`PSSO_KEYPATH`, `PSSO_ENDPOINTJWKS` …) are pre‑populated in
`.env.psso` and rarely need changes.

---

## 3  Integrate with the macOS Profile

1. Build & notarize the **Argio SSO** extension (see that repo’s README).  
2. Import `deployment/argio_PSSO.mobileconfig` into Mosyle.  
   *ExtensionIdentifier* must equal your macOS bundle ID  
   (`ch.argio.sso.extension-macos`).  
3. Assign package + profile to a test Mac, reboot → login with Authentik user.

---

## 4  Common Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| macOS login window ignores cloud creds | wrong `Issuer` or server TLS issue | check profile keys + `.well‑known/apple-app-site-association` |
| “invalid_grant” in server log | wrong client secret | match secret in Authentik Application |
| `/healthz` OK, but 404 on `/v1/user/token` | container didn’t pick up env paths | `docker compose exec psso env | grep PSSO_USER_REG_PATH` |

---

## 5  Next Steps / Ideas

* Switch `AuthenticationMethod` to **Key** for password‑less login  
* Add **SCIM** sync so Authentik auto‑creates Managed Apple IDs in ABM  
* Enable Device‑Attestation (macOS 15) by setting `UseSharedDeviceKeys = true`

---

## Contribution / License

Code is MIT‑licensed (same as upstream Twocanoes).  
Feel free to open PRs or issues in the [Argon‑Analytik](https://github.com/argon-analytik) org.
PRs should pass `go vet` and the basic health‑check compose test.

Happy cloud logins! 🚀
```
