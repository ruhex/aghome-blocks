#!/usr/bin/env python3
"""Domain classification per the dns-analisis skill v3.0 methodology.

Priority: host rules -> suffix rules (longest match) -> weak keyword signals -> REVIEW.
v3 policy: first-party does not imply privacy-safe; unnecessary telemetry / aggressive analytics
is BLOCKed on strong evidence, else OPTIONAL/REVIEW.
"""
import json
import os
import re
import sys

SRC = sys.argv[1] if len(sys.argv) > 1 else "analysis/allowed_domains.json"
OUT = sys.argv[2] if len(sys.argv) > 2 else "analysis/dns-analysis.json"

LOCAL_SUFFIXES = (".lan", ".local", ".home", ".internal", ".localdomain", ".arpa")

# ---------------------------------------------------------------- constructors
def risks(sec=5, priv=15, trk=5, dc=15, prof=5, adv=5, brk=30):
    return {"security_risk": sec, "privacy_risk": priv, "tracking_risk": trk,
            "data_collection_risk": dc, "profiling_risk": prof, "advertising_risk": adv,
            "breakage_risk": brk}

def dcol(cls, **sens):
    base = {"identity": 0, "device": 0, "network": 0, "location": 0, "behavior": 0,
            "content": 0, "advertising": 0}
    base.update(sens)
    base["class"] = cls
    return base

def R(cls, owner, scale, crit, cats, dc, rk, ev_type, ev_str, ev_desc, fp=None, hard=None):
    return {"cls": cls, "owner": owner, "scale": scale, "crit": crit, "cats": cats,
            "dc": dc, "rk": rk, "ev": ({"type": ev_type, "strength": ev_str, "description": ev_desc} if ev_type else None),
            "fp": fp, "hard": hard or []}

# ---------------------------------------------------------------- rule groups
def core(owner, scale="LARGE", crit="HIGH", cats=("CORE_FUNCTIONAL", "API"), priv=15, desc=None):
    return R("SAFE", owner, scale, crit, list(cats), dcol("TECHNICAL", network=25),
             risks(priv=priv, brk=60), "core_api_or_infrastructure", "STRONG",
             desc or f"Core functionality of {owner}: blocking breaks the service")

def cdn(owner, scale="LARGE", crit="HIGH"):
    return R("SAFE", owner, scale, crit, ["CDN"], dcol("TECHNICAL", network=25),
             risks(priv=15, brk=55), "essential_cdn", "STRONG",
             f"{owner} CDN infrastructure: blocking breaks content delivery")

def content(owner, cats=("CONTENT",), crit="HIGH"):
    return R("SAFE", owner, "LARGE", crit, list(cats), dcol("TECHNICAL", network=25, content=20),
             risks(priv=20, brk=55), "core_content_service", "STRONG",
             f"Primary service of {owner}: blocking breaks access")

def dev(owner, crit="HIGH"):
    return R("SAFE", owner, "LARGE", crit, ["DEVELOPER_INFRASTRUCTURE", "PACKAGE_REPOSITORY"],
             dcol("TECHNICAL", network=25), risks(priv=12, brk=60), "developer_infrastructure", "STRONG",
             f"{owner} developer infrastructure")

def blocker_ads(owner):
    return R("BLOCK", owner, "LARGE", "LOW", ["ADVERTISING", "TRACKING", "PROFILING"],
             dcol("ADVERTISING", identity=55, device=70, network=55, behavior=80, advertising=95),
             risks(sec=5, priv=95, trk=100, dc=90, prof=85, adv=100, brk=5),
             "known_ad_network", "STRONG",
             f"{owner}: documented advertising infrastructure (auctions, attribution, targeting)",
             fp=False, hard=["HARD_PRIVACY_ADVERTISING", "HARD_PRIVACY_TRACKING"])

def blocker_tracker(owner, desc_extra=""):
    return R("BLOCK", owner, "LARGE", "LOW", ["TRACKING", "ANALYTICS", "PROFILING"],
             dcol("MULTI_CATEGORY", identity=60, device=80, network=60, behavior=90, advertising=70),
             risks(sec=5, priv=95, trk=100, dc=90, prof=85, adv=70, brk=5),
             "known_tracker", "STRONG",
             f"{owner}: classified as cross-site tracking infrastructure{desc_extra}",
             fp=False, hard=["HARD_PRIVACY_TRACKING"])

def blocker_attr(owner):
    return R("BLOCK", owner, "LARGE", "LOW", ["ATTRIBUTION", "TRACKING", "ADVERTISING"],
             dcol("MULTI_CATEGORY", identity=65, device=80, network=60, behavior=85, advertising=95),
             risks(sec=5, priv=92, trk=95, dc=88, prof=85, adv=100, brk=5),
             "third_party_attribution", "STRONG",
             f"{owner}: mobile/ad attribution and conversion tracking",
             fp=False, hard=["HARD_PRIVACY_TRACKING", "HARD_PRIVACY_ADVERTISING"])

def telemetry_opt(owner, desc):
    return R("OPTIONAL", owner, "LARGE", "LOW", ["TELEMETRY", "ANALYTICS"],
             dcol("BEHAVIOR", device=45, network=40, behavior=65),
             risks(sec=5, priv=50, trk=35, dc=50, prof=35, adv=5, brk=20),
             "known_telemetry", "MEDIUM",
             desc, fp=None)

def unk():
    return R("REVIEW", None, None, "UNKNOWN", ["UNKNOWN"], dcol("UNKNOWN", identity=10, device=10,
             network=10, behavior=10, content=10, advertising=10),
             risks(sec=10, priv=15, trk=10, dc=15, prof=5, adv=5, brk=25), None, None, None)

# ---------------------------------------------------------------- host rules
HOST_RULES = {
    "analytics.google.com": blocker_tracker("Google Analytics"),
    "adservice.google.com": blocker_ads("Google Ads"),
    "www.googleadservices.com": blocker_ads("Google Ads"),
    "connect.facebook.net": R("BLOCK", "Meta Pixel", "LARGE", "LOW", ["TRACKING", "ADVERTISING", "PROFILING"],
                              dcol("MULTI_CATEGORY", identity=65, device=80, network=60, behavior=90, advertising=90),
                              risks(sec=5, priv=96, trk=100, dc=92, prof=90, adv=90, brk=5),
                              "confirmed_tracking_endpoint", "STRONG",
                              "Meta/Facebook pixel: cross-site identification and ad tracking",
                              fp=False, hard=["HARD_PRIVACY_TRACKING"]),
    "mc.yandex.ru": R("BLOCK", "Yandex Metrica", "LARGE", "LOW", ["TRACKING", "ANALYTICS", "BEHAVIORAL_DATA"],
                      dcol("MULTI_CATEGORY", identity=55, device=75, network=55, behavior=90, advertising=60),
                      risks(sec=5, priv=92, trk=100, dc=85, prof=80, adv=60, brk=12),
                      "known_tracker", "STRONG",
                      "Yandex Metrica: documented cross-site analytics and visitor identification; widely classified as a tracker",
                      fp=False, hard=["HARD_PRIVACY_TRACKING"]),
    "analytics.brew.sh": R("OPTIONAL", "Homebrew", "MEDIUM", "LOW", ["TELEMETRY", "USAGE_METRICS"],
                           dcol("BEHAVIOR", device=40, behavior=55),
                           risks(sec=5, priv=35, trk=20, dc=40, prof=20, adv=0, brk=10),
                           "known_telemetry", "STRONG",
                           "Homebrew analytics is documented by the project itself (aggregated install stats); does not affect brew operation",
                           fp=True),
    # --- extensions from the monthly dataset ---
    "miro.com": content("Miro", cats=("CONTENT", "API")),
    "mirostatic.com": cdn("Miro"),
    "steamconnecttest.com": R("SAFE", "Valve (Steam)", "LARGE", "MEDIUM", ["GAME_INFRASTRUCTURE"],
                              dcol("TECHNICAL", network=30), risks(priv=15, brk=20),
                              "connectivity_check", "STRONG", "Steam connectivity check"),
    "openrouter.ai": dev("OpenRouter (AI gateway)"),
    "iterm2.com": dev("iTerm2"),
    "proxmox.com": R("SAFE", "Proxmox", "MEDIUM", "HIGH", ["UPDATE", "DEVELOPER_INFRASTRUCTURE"],
                     dcol("TECHNICAL", network=25), risks(priv=12, brk=60), "update_service", "STRONG",
                     "Proxmox VE updates"),
    "turnkeylinux.org": dev("TurnKey Linux"),
    "jquery.com": cdn("jQuery CDN"),
    "revenuecat.com": R("SAFE", "RevenueCat", "MEDIUM", "HIGH", ["PAYMENT", "API"],
                        dcol("IDENTITY", identity=40, network=30), risks(priv=35, dc=40, brk=65),
                        "payment_infrastructure", "STRONG", "App subscription management: blocking breaks purchases",
                        fp=False),
    "digital.gov.ru": R("SAFE", "RU Ministry of Digital Development", "LARGE", "HIGH", ["API", "CORE_FUNCTIONAL"],
                        dcol("IDENTITY", identity=45, network=30), risks(priv=35, dc=40, brk=70),
                        "government_infrastructure", "STRONG", "Government digital platform infrastructure", fp=True),
    "smartthings.com": R("SAFE", "Samsung SmartThings", "LARGE", "HIGH", ["CORE_FUNCTIONAL"],
                         dcol("TECHNICAL", device=40), risks(priv=30, dc=35, brk=65),
                         "core_iot_backend", "STRONG", "Samsung SmartThings smart home", fp=True),
    "samsungcloud.tv": R("SAFE", "Samsung (Smart TV)", "LARGE", "HIGH", ["API", "CORE_FUNCTIONAL"],
                         dcol("TECHNICAL", device=40), risks(priv=30, dc=35, brk=65),
                         "core_iot_backend", "STRONG", "Samsung Smart TV cloud", fp=True),
    "samsungnyc.com": cdn("Samsung CDN"),
    "amazonvideo.com": content("Amazon Prime Video"),
    "apple.news": content("Apple News", cats=("CONTENT",)),
    "googlezip.net": R("SAFE", "Google", "LARGE", "MEDIUM", ["CORE_FUNCTIONAL"],
                       dcol("TECHNICAL", network=40), risks(priv=25, brk=30),
                       "traffic_optimization_proxy", "STRONG", "Google traffic optimization tunnel", fp=True),
    "cloudflare.net": cdn("Cloudflare"),
    "fastlydns.net": cdn("Fastly"),
    "fastly-masque.net": R("SAFE", "Fastly/Masque (Apple Private Relay)", "LARGE", "HIGH", ["CDN", "CORE_FUNCTIONAL"],
                           dcol("NONE"), risks(priv=10, brk=55), "private_relay_edge", "STRONG",
                           "Apple Private Relay edges on Fastly", fp=None),
    "fbsbx.com": cdn("Meta CDN"),
    "globalsign.com": R("SAFE", "GlobalSign", "LARGE", "CRITICAL", ["CERTIFICATE"], dcol("NONE"),
                        risks(priv=5, brk=75), "certificate_infrastructure", "STRONG",
                        "GlobalSign OCSP / certificate infrastructure"),
    "adtidy.org": R("SAFE", "AdGuard", "LARGE", "HIGH", ["UPDATE", "DEVELOPER_INFRASTRUCTURE"],
                    dcol("TECHNICAL", network=25), risks(priv=12, brk=55), "update_service", "STRONG",
                    "AdGuard extension updates", fp=True),
    "intellij.net": R("SAFE", "JetBrains", "LARGE", "HIGH", ["UPDATE", "DEVELOPER_INFRASTRUCTURE"],
                      dcol("TECHNICAL", network=25), risks(priv=12, brk=55), "update_service", "STRONG",
                      "JetBrains update checks", fp=True),
    "selcdn.net": R("SAFE", "Selectel", "MEDIUM", "HIGH", ["CDN", "CLOUD_STORAGE"],
                    dcol("TECHNICAL", network=25), risks(priv=15, brk=55), "essential_cloud", "STRONG",
                    "Selectel cloud/CDN"),
    "cdnnow.ru": cdn("CDNnow (RU)", scale="MEDIUM"),
    "naydex.net": R("SAFE", "Yandex", "LARGE", "HIGH", ["CDN"], dcol("TECHNICAL", network=25),
                    risks(priv=18, brk=55), "essential_cdn", "STRONG", "Yandex CDN edges (maps)", fp=True),
    "aibixby.com": R("SAFE", "Samsung Bixby", "LARGE", "MEDIUM", ["API", "CORE_FUNCTIONAL"],
                     dcol("TECHNICAL", device=40), risks(priv=30, dc=35, brk=55),
                     "voice_assistant_backend", "STRONG", "Bixby provisioning (Samsung)", fp=True),
    "ivi.ru": content("IVI (online cinema)"),
    "tbank-online.com": R("SAFE", "T-Bank", "LARGE", "CRITICAL", ["PAYMENT", "AUTHENTICATION"],
                          dcol("IDENTITY", identity=50, network=30), risks(priv=35, dc=45, brk=75),
                          "authentication_and_payment", "STRONG", "Bank: authentication/payments", fp=True),
    "tinkoffinsurance.ru": R("SAFE", "T-Insurance", "LARGE", "HIGH", ["PAYMENT", "API"],
                             dcol("IDENTITY", identity=45, network=30), risks(priv=32, dc=40, brk=70),
                             "payment_infrastructure", "STRONG", "T-Bank insurance service", fp=True),
    "tinsurance.ru": R("SAFE", "T-Insurance", "LARGE", "HIGH", ["PAYMENT", "API"],
                       dcol("IDENTITY", identity=45, network=30), risks(priv=32, dc=40, brk=70),
                       "payment_infrastructure", "STRONG", "T-Bank insurance service", fp=True),
    "yandex.kz": R("SAFE", "Yandex", "LARGE", "HIGH", ["API", "AUTHENTICATION", "CONTENT"],
                   dcol("IDENTITY", identity=40, network=30), risks(priv=25, dc=30, brk=60),
                   "core_service", "STRONG", "Yandex (regional domain): accounts/services", fp=True),
    "yandex.fi": R("SAFE", "Yandex", "LARGE", "HIGH", ["API", "AUTHENTICATION", "CONTENT"],
                   dcol("IDENTITY", identity=40, network=30), risks(priv=25, dc=30, brk=60),
                   "core_service", "STRONG", "Yandex (regional domain): accounts/services", fp=True),
}

# ---------------------------------------------------------------- suffix rules
SUFFIX_RULES = {
    **{s: R("SAFE", None, None, "UNKNOWN", ["CORE_FUNCTIONAL"], dcol("NONE"),
            risks(sec=0, priv=0, trk=0, dc=0, prof=0, adv=0, brk=5), "local_network_name", "STRONG",
            "Local LAN hostname (resolved locally, external tracking impossible)", fp=True)
       for s in LOCAL_SUFFIXES},
    # Apple
    **{s: core("Apple", cats=("CORE_FUNCTIONAL", "API"), priv=20) for s in (
        "apple.com", "icloud.com", "icloud-content.com", "cdn-apple.com", "mzstatic.com",
        "aaplimg.com", "apple-dns.net", "push-apple.com", "origin-apple.com", "ls-apple.com", "me.com",
        "apple-cloudkit.com")},
    "ls.apple.com": R("SAFE", "Apple Location Services", "LARGE", "HIGH", ["CORE_FUNCTIONAL", "LOCATION"],
                      dcol("LOCATION", location=55, device=40, network=35),
                      risks(sec=5, priv=35, trk=10, dc=35, prof=10, adv=0, brk=70),
                      "core_location_service", "STRONG",
                      "Apple location services: queries are functional (maps/suggestions), blocking breaks geo features",
                      fp=True),
    # Akamai/CDN
    **{s: cdn("Akamai") for s in ("akadns.net", "akamaiedge.net", "akamaihd.net", "akamaized.net",
                                  "edgekey.net", "edgesuite.net", "akamai.net", "akahost.net")},
    "fastly.net": cdn("Fastly"),
    "fastly-edge.com": cdn("Fastly"),
    "cdn77.org": cdn("CDN77", scale="MEDIUM"),
    "cdnvideo.ru": cdn("CDNvideo (RU)", scale="MEDIUM"),
    "edgecdn.ru": cdn("EdgeCDN (RU)", scale="MEDIUM"),
    "trbcdn.net": cdn("TRB CDN (RU)", scale="MEDIUM"),
    "ngenix.net": cdn("Ngenix (RU)", scale="MEDIUM"),
    "yccdn.ru": cdn("Yandex Cloud CDN (RU)", scale="LARGE"),
    "aliyunga0017.com": cdn("Alibaba Cloud (Aliyun) edge", scale="LARGE"),
    "initaa.com": R("SAFE", "CDN edge domain (generic)", "MEDIUM", "HIGH", ["CDN"],
                    dcol("TECHNICAL", network=25), risks(priv=15, brk=55), "observed_cname_infrastructure",
                    "STRONG", "Generic CDN edge zone; operator-independent",
                    fp=None),
    # Google
    **{s: core("Google", cats=("CORE_FUNCTIONAL", "API"), priv=20) for s in (
        "google.com", "googleapis.com", "gmail.com", "googlemail.com", "recaptcha.net", "gvt1.com", "gvt2.com")},
    **{s: R("SAFE", "Google", "LARGE", "HIGH", ["CONTENT", "CDN"], dcol("TECHNICAL", network=25, content=20),
            risks(priv=20, brk=55), "core_content_service", "STRONG",
            "Google content delivery (YouTube/avatars): blocking breaks the service") for s in (
        "gstatic.com", "googleusercontent.com", "googlevideo.com", "youtube.com", "ytimg.com",
        "youtube-nocookie.com", "ggpht.com")},
    # Microsoft/Azure
    **{s: R("SAFE", "Microsoft", "LARGE", "CRITICAL", ["UPDATE", "CORE_FUNCTIONAL"],
            dcol("TECHNICAL", network=25), risks(priv=18, brk=70), "os_update_service", "STRONG",
            "Microsoft OS updates/core: blocking breaks updates and OS operation") for s in (
        "microsoft.com", "windows.com", "windowsupdate.com", "update.microsoft.com", "download.microsoft.com",
        "live.com", "office.com", "office.net", "msocsp.com", "msftconnecttest.com", "msftauth.net",
        "msftauthimages.net", "msedge.net", "bing.com", "onedrive.com", "sharepoint.com", "svc.ms", "msappproxy.net")},
    **{s: R("SAFE", "Microsoft Azure", "LARGE", "HIGH", ["CDN", "CLOUD_STORAGE"],
            dcol("TECHNICAL", network=25), risks(priv=15, brk=55), "essential_cloud", "STRONG",
            "Azure cloud infrastructure: blocking breaks applications") for s in (
        "azurefd.net", "tm-azurefd.net", "azureedge.net", "windows.net", "azure.com", "azurewebsites.net",
        "cloudapp.net", "trafficmanager.net")},
    # CDN/cloud
    "cloudflare.com": cdn("Cloudflare"),
    "cloudflare-dns.com": R("SAFE", "Cloudflare DNS", "LARGE", "CRITICAL", ["DNS"],
                            dcol("NONE"), risks(priv=10, brk=70), "dns_infrastructure", "STRONG",
                            "Cloudflare DNS resolver"),
    "cloudflareclient.com": R("SAFE", "Cloudflare WARP", "LARGE", "HIGH", ["CORE_FUNCTIONAL"],
                              dcol("TECHNICAL", network=30), risks(priv=15, brk=60),
                              "vpn_infrastructure", "STRONG", "Cloudflare WARP VPN tunnels"),
    "workers.dev": dev("Cloudflare Workers"),
    "pages.dev": dev("Cloudflare Pages"),
    "amazonaws.com": R("SAFE", "AWS", "LARGE", "HIGH", ["CDN", "CLOUD_STORAGE"],
                       dcol("TECHNICAL", network=25), risks(priv=15, brk=55), "essential_cloud", "STRONG",
                       "AWS cloud infrastructure"),
    "cloudfront.net": cdn("Amazon CloudFront"),
    "amazon.com": content("Amazon", cats=("CONTENT", "PAYMENT")),
    "media-amazon.com": cdn("Amazon CDN"),
    "ssl-images-amazon.com": cdn("Amazon CDN"),
    # dev
    **{s: dev("GitHub") for s in ("github.com", "githubusercontent.com", "githubassets.com",
                                  "github.io", "ghcr.io", "githubcopilot.com")},
    **{s: dev("GitLab") for s in ("gitlab.com", "gitlab-static.net")},
    **{s: dev("JetBrains") for s in ("jetbrains.com", "jetbrains.ai", "jetbrains.cloud",
                                     "youtrack.cloud", "intellij.com")},
    "codeium.com": dev("Codeium"),
    "jina.ai": dev("Jina AI"),
    "visualstudio.com": R("SAFE", "Microsoft (VS Code/ADO)", "LARGE", "HIGH",
                          ["DEVELOPER_INFRASTRUCTURE", "UPDATE"], dcol("TECHNICAL", network=25),
                          risks(priv=15, brk=60), "update_service", "STRONG",
                          "VS Code updates and Microsoft dev infrastructure"),
    "vscode-cdn.net": cdn("VS Code CDN"),
    "vscodeusercontent.com": cdn("VS Code CDN"),
    "oisd.nl": dev("OISD (DNS blocklists)"),
    **{s: dev("Package registries / docs") for s in (
        "docker.io", "docker.com", "gcr.io", "k8s.io", "quay.io", "pypi.org", "files.pythonhosted.org",
        "pythonhosted.org", "npmjs.com", "npmjs.org", "jsdelivr.net", "unpkg.com", "cdnjs.com",
        "crates.io", "rust-lang.org", "golang.org", "go.dev", "gopkg.in", "debian.org", "ubuntu.com",
        "launchpad.net", "alpinelinux.org", "archlinux.org", "fedoraproject.org", "brew.sh",
        "stackoverflow.com", "stackexchange.com", "ietf.org", "ollama.com", "nuget.org", "fwupd.org",
        "gravatar.com", "duckduckgo.com")},
    # AI
    **{s: core("AI service", cats=("API", "CORE_FUNCTIONAL"), priv=18) for s in (
        "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com", "anthropic.com", "claude.ai",
        "z.ai", "bigmodel.cn", "zhipuai.cn", "deepseek.com", "mistral.ai", "x.ai", "grok.com",
        "perplexity.ai", "pplx.ai", "cursor.sh", "cursor.com", "huggingface.co", "hf.co")},
    # VPN/game
    "zerotier.com": R("SAFE", "ZeroTier", "MEDIUM", "CRITICAL", ["API", "CORE_FUNCTIONAL"],
                      dcol("TECHNICAL", network=35), risks(priv=15, brk=70),
                      "vpn_control_plane", "STRONG", "ZeroTier control plane: blocking breaks the VPN"),
    "transmissionbt.com": R("SAFE", "Transmission", "SMALL", "LOW", ["CORE_FUNCTIONAL"],
                            dcol("NETWORK", network=45), risks(priv=20, brk=15),
                            "client_builtin_service", "STRONG",
                            "Built-in external IP check of the Transmission torrent client"),
    **{s: R("SAFE", "gaming platforms", "LARGE", "HIGH", ["GAME_INFRASTRUCTURE"],
            dcol("TECHNICAL", device=30, network=30, behavior=20), risks(priv=22, trk=10, dc=30, prof=12, brk=60),
            "game_backend_required", "STRONG", "Game backends: blocking breaks gameplay") for s in (
        "warthunder.com", "gaijinent.com", "gaijin.net", "steampowered.com", "steamcontent.com",
        "steamstatic.com", "steamserver.net", "steamcommunity.com", "epicgames.com", "unrealengine.com",
        "playstation.net", "xboxlive.com", "xbox.com", "nintendo.com", "nintendo.net", "riotgames.com")},
    # Samsung/Xiaomi
    "samsungqbe.com": R("SAFE", "Samsung (smart appliances)", "LARGE", "HIGH", ["CORE_FUNCTIONAL", "TELEMETRY"],
                        dcol("TECHNICAL", device=45, behavior=30), risks(priv=35, trk=15, dc=40, prof=15, brk=65),
                        "core_iot_backend", "STRONG", "Samsung smart appliance backend: blocking breaks device features",
                        fp=True),
    "samsungcloudsolution.com": R("SAFE", "Samsung", "LARGE", "HIGH", ["CORE_FUNCTIONAL"],
                                  dcol("TECHNICAL", device=40), risks(priv=30, dc=35, brk=65),
                                  "core_iot_backend", "STRONG", "Samsung cloud services", fp=True),
    "samsung.com": core("Samsung"),
    "samsungcloud.com": R("SAFE", "Samsung Cloud", "LARGE", "HIGH", ["CLOUD_STORAGE"],
                          dcol("TECHNICAL", device=35), risks(priv=25, brk=60), "essential_cloud", "STRONG",
                          "Samsung Cloud"),
    "samsungosp.com": R("SAFE", "Samsung Push", "LARGE", "HIGH", ["PUSH_NOTIFICATION"],
                        dcol("TECHNICAL", device=35), risks(priv=20, brk=60),
                        "push_infrastructure", "STRONG", "Samsung push infrastructure", fp=True),
    "mi.com": R("SAFE", "Xiaomi (Mi Home/IoT)", "LARGE", "HIGH", ["API", "CORE_FUNCTIONAL"],
                dcol("TECHNICAL", device=45, behavior=25), risks(priv=32, trk=12, dc=40, prof=12, brk=65),
                "core_iot_backend", "STRONG", "Xiaomi device cloud: blocking breaks Mi Home / devices",
                fp=True),
    "xiaomi.com": core("Xiaomi"),
    "miui.com": core("Xiaomi"),
    # Yandex
    **{s: R("SAFE", "Yandex", "LARGE", "HIGH", ["API", "CONTENT", "CDN"],
            dcol("TECHNICAL", network=30, content=20), risks(priv=25, trk=8, dc=30, prof=8, brk=60),
            "core_service", "STRONG", "Core Yandex services: blocking breaks access") for s in (
        "yandex.ru", "yandex.net", "yandex.com", "ya.ru", "yandexcloud.net", "yastatic.net", "yandex-team.ru")},
    # VK/Mail.ru
    **{s: content("VK", cats=("SOCIAL", "API", "CONTENT")) for s in (
        "vk.com", "vk.ru", "userapi.com", "vkuser.net", "vk-cdn.net", "vk-cdn.com", "mycdn.me")},
    **{s: content("Mail.ru", cats=("SOCIAL", "API", "CONTENT")) for s in (
        "mail.ru", "imgsmail.ru", "list.ru", "bk.ru", "inbox.ru", "internet.ru")},
    # RU services
    **{s: content("RU retail / marketplaces", cats=("CONTENT", "API", "PAYMENT")) for s in (
        "avito.ru", "hh.ru", "ozon.ru", "wildberries.ru", "wbbasket.ru",
        "aliexpress.ru", "magnit.ru", "samokat.ru", "vseinstrumenti.ru", "gmonit.ru")},
    **{s: R("SAFE", "RU banks / gov services", "LARGE", "CRITICAL", ["PAYMENT", "AUTHENTICATION"],
            dcol("IDENTITY", identity=50, network=30), risks(priv=35, dc=45, brk=75),
            "authentication_and_payment", "STRONG",
            "Bank/gov services: authentication and payments, blocking is unacceptable") for s in (
        "tinkoff.ru", "tbank.ru", "t-bank-app.ru", "cdn-tinkoff.ru", "t-static.ru", "sber.ru", "sberbank.ru",
        "sbrf.ru", "gosuslugi.ru", "nalog.ru", "nalog.gov.ru", "mos.ru")},
    # messengers / social
    **{s: R("SAFE", "Telegram", "LARGE", "HIGH", ["PUSH_NOTIFICATION", "SOCIAL", "API"],
            dcol("TECHNICAL", network=30), risks(priv=15, brk=60), "push_infrastructure", "STRONG",
            "Telegram messenger: blocking breaks message delivery", fp=True) for s in (
        "telegram.org", "cdn-telegram.org", "t.me", "telesco.pe", "tdesktop.com")},
    **{s: content("WhatsApp", cats=("SOCIAL", "PUSH_NOTIFICATION")) for s in ("whatsapp.com", "whatsapp.net")},
    "facebook.com": content("Facebook/Meta", cats=("SOCIAL",)),
    "fbcdn.net": cdn("Meta CDN"),
    "cdninstagram.com": cdn("Meta CDN"),
    "instagram.com": content("Instagram", cats=("SOCIAL",)),
    "twitter.com": content("X/Twitter", cats=("SOCIAL",)),
    "x.com": content("X/Twitter", cats=("SOCIAL",)),
    "twimg.com": cdn("X/Twitter CDN"),
    # media
    **{s: content("streaming platforms") for s in (
        "netflix.com", "nflxvideo.net", "nflximg.net", "nflxso.net", "spotify.com", "scdn.co",
        "spotifycdn.com", "twitch.tv", "twitchcdn.net", "jtvnw.net", "rutube.ru")},
    # cert/time
    **{s: R("SAFE", "PKI", "LARGE", "CRITICAL", ["CERTIFICATE"], dcol("NONE"),
            risks(priv=5, brk=75), "certificate_infrastructure", "STRONG",
            "Certificate infrastructure: blocking breaks TLS checks") for s in (
        "letsencrypt.org", "digicert.com", "sectigo.com", "godaddy.com", "entrust.net", "pki.goog")},
    "ntp.org": R("SAFE", "NTP pools", "MEDIUM", "CRITICAL", ["CORE_FUNCTIONAL"], dcol("NETWORK", network=40),
                 risks(priv=10, brk=70), "time_synchronization", "STRONG", "Time synchronization"),
    # --- BLOCK: ads / tracking / attribution ---
    **{s: blocker_ads(svc) for s, svc in {
        "doubleclick.net": "Google DoubleClick", "googleadservices.com": "Google Ads",
        "googlesyndication.com": "Google AdSense", "googletagservices.com": "Google Ad Manager",
        "admob.com": "Google AdMob", "taboola.com": "Taboola", "outbrain.com": "Outbrain",
        "criteo.com": "Criteo", "criteo.net": "Criteo", "pubmatic.com": "PubMatic",
        "rubiconproject.com": "Magnite/Rubicon", "openx.net": "OpenX", "adnxs.com": "Xandr (AppNexus)",
        "casalemedia.com": "Casale Media", "smartadserver.com": "SmartAdServer",
        "sharethrough.com": "Sharethrough", "33across.com": "33Across", "moatads.com": "Oracle Moat",
        "adsafeprotected.com": "IAS (ad verification)", "doubleverify.com": "DoubleVerify"}.items()},
    **{s: blocker_tracker(svc) for s, svc in {
        "google-analytics.com": "Google Analytics", "facebook.net": "Meta Pixel",
        "ads-twitter.com": "X/Twitter Pixel", "twttr.com": "X/Twitter tracking",
        "scorecardresearch.com": "comScore", "quantserve.com": "Quantcast"}.items()},
    **{s: blocker_attr(svc) for s, svc in {
        "demdex.net": "Adobe Audience Manager", "2o7.net": "Adobe Analytics", "omtrdc.net": "Adobe Analytics",
        "branch.io": "Branch", "appsflyer.com": "AppsFlyer", "adjust.com": "Adjust",
        "kochava.com": "Kochava"}.items()},
    # --- OPTIONAL: telemetry / analytics ---
    **{s: telemetry_opt(svc, f"{svc}: telemetry/analytics, meaningful privacy benefit from blocking") for s, svc in {
        "app-measurement.com": "Google Analytics for Firebase", "crashlytics.com": "Firebase Crashlytics",
        "sentry.io": "Sentry", "clarity.ms": "Microsoft Clarity", "amplitude.com": "Amplitude",
        "mixpanel.com": "Mixpanel", "segment.io": "Segment", "segment.com": "Segment",
        "hotjar.com": "Hotjar", "fullstory.com": "FullStory", "umeng.com": "Umeng",
        "appmetrica.yandex.net": "AppMetrica", "adobedtm.com": "Adobe DTM",
        "googletagmanager.com": "Google Tag Manager", "cloudflareinsights.com": "Cloudflare Web Analytics"}.items()},
}

WEAK_KW = re.compile(
    r"(track|telemetr|analytic|metric|beacon|pixel|collect|affiliate|attribution|adserver|^ads?[.\-]|[.\-]ads?[.\-]|^ad[0-9])")

MULTI_SUFFIX = ("co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "com.cn", "com.tr", "com.br",
                "com.ua", "kiev.ua", "co.il", "com.sg", "co.kr", "co.za", "com.ar", "com.hk",
                "com.tw", "com.pl", "co.jp", "co.in", "com.mx", "org.ru", "net.ru", "com.ru", "msk.ru")


def parent_domain(host):
    parts = host.split(".")
    for i in range(len(parts) - 1):
        if ".".join(parts[i:]) in MULTI_SUFFIX:
            return ".".join(parts[i - 1:]) if i else ".".join(parts)
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


OPERATOR_DOMAINS = set()


def classify(host):
    # 0) operator-owned infrastructure (gitignored file)
    for od in OPERATOR_DOMAINS:
        if host == od or host.endswith("." + od):
            return own_rule(), [{"type": "own_infrastructure", "strength": "STRONG",
                                 "description": f"Operator domain ({od}) from operator-domains.txt"}]
    # 1) exact host-rule match
    if host in HOST_RULES and HOST_RULES[host] is not None:
        r = HOST_RULES[host]
        return r, [r["ev"]] if r["ev"] else []
    # 2) host-rule keys as suffixes (subdomain coverage), longest key
    best = None
    for key, rule in HOST_RULES.items():
        if rule is not None and host.endswith("." + key):
            if best is None or len(key) > len(best[0]):
                best = (key, rule)
    if best:
        return best[1], [best[1]["ev"]] if best[1]["ev"] else []
    # 3) zone suffix rules, longest suffix
    for suffix, rule in SUFFIX_RULES.items():
        if suffix.startswith("."):
            matched = host.endswith(suffix)
        else:
            matched = host == suffix or host.endswith("." + suffix)
        if matched and (best is None or len(suffix) > len(best[0])):
            best = (suffix, rule)
    if best:
        return best[1], [best[1]["ev"]] if best[1]["ev"] else []
    if WEAK_KW.search(host):
        r = unk()
        r["cls"] = "REVIEW"
        r["rk"] = risks(sec=15, priv=35, trk=30, dc=35, prof=20, adv=25, brk=25)
        r["ev"] = {"type": "tracking_keyword", "strength": "WEAK",
                   "description": "Suspicious keyword in hostname - weak signal"}
        return r, [r["ev"]]
    return unk(), []


def to_domain_obj(host, rule, ev_list, queries, clients, whitelisted, first_seen, last_seen):
    counts = {"STRONG": 0, "MEDIUM": 0, "WEAK": 0}
    for e in ev_list:
        counts[e["strength"]] += 1
    return {
        "domain": host,
        "classification": rule["cls"],
        "confidence": {"BLOCK": 85, "OPTIONAL": 65, "REVIEW": 25, "SAFE": 80}[rule["cls"]],
        **rule["rk"],
        "first_party": rule["fp"],
        "service_owner": rule["owner"],
        "ecosystem_scale": rule["scale"],
        "service_criticality": rule["crit"],
        "category": rule["cats"],
        "data_collection": rule["dc"],
        "known_service": rule["owner"],
        "parent_domain": parent_domain(host),
        "cname": None,
        "resolved_ips": [],
        "external_intelligence": {k: {"status": "NOT_QUERIED"} for k in
                                  ("virustotal", "google_web_risk", "abuseipdb", "rdap", "urlhaus")},
        "decision_basis": {
            "strong_signals": counts["STRONG"], "medium_signals": counts["MEDIUM"], "weak_signals": counts["WEAK"],
            "external_sources_used": [], "external_sources_supporting": [], "external_sources_conflicting": [],
            "hard_rules_triggered": rule["hard"] if rule["cls"] == "BLOCK" else [],
            "negative_evidence": [e for e in ev_list if e["weight"] < 0] if all("weight" in e for e in ev_list) else [],
        },
        "evidence": ev_list,
        "reason": {
            "BLOCK": "Confirmed privacy-invasive/ad infrastructure with low breakage risk (hard privacy rule)",
            "OPTIONAL": "Likely telemetry/analytics with a meaningful privacy benefit, but evidence or breakage risk does not justify an unconditional BLOCK",
            "REVIEW": "Insufficient evidence or unknown function - uncertainty is not turned into blocking",
            "SAFE": "Core service functionality: blocking likely breaks it; no meaningful invasive telemetry on this endpoint",
        }[rule["cls"]],
        "recommended_action": {"BLOCK": "BLOCK", "OPTIONAL": "OPTIONAL", "REVIEW": "REVIEW", "SAFE": "SAFE"}[rule["cls"]],
        "recommended_rule": f"||{host}^",
        "queries_period": queries,
        "clients": clients,
        "whitelisted": whitelisted,
        "first_seen_utc": first_seen,
        "last_seen_utc": last_seen,
    }


def load_operator_domains():
    """Optional gitignored file: one domain per line (own infrastructure).

    Those domains classify as SAFE (own_infrastructure) and never
    reach the blocklist.
    """
    path = os.path.join(os.path.dirname(SRC) or ".", "operator-domains.txt")
    if not os.path.exists(path):
        return []
    doms = []
    for line in open(path):
        d = line.split("#")[0].strip().lower().lstrip(".")
        if d:
            doms.append(d)
    return doms


def own_rule():
    return R("SAFE", "operator (own infrastructure)", "SMALL", "HIGH", ["CORE_FUNCTIONAL"],
             dcol("NONE"), risks(sec=5, priv=5, brk=35), "own_infrastructure", "STRONG",
             "Domain from operator-domains.txt", fp=True)


def load_operator_rules():
    """Optional gitignored file: operator-specific classification rules.

    {"host": {...}, "suffix": {...}} in the internal rule format. Keeps
    traffic-derived rules out of the public package.
    """
    path = os.path.join(os.path.dirname(SRC) or ".", "operator-rules.json")
    if not os.path.exists(path):
        return {"host": {}, "suffix": {}}
    return json.load(open(path))


def main():
    OPERATOR_DOMAINS.update(load_operator_domains())
    operator_rules = load_operator_rules()
    for k, v in operator_rules["host"].items():
        HOST_RULES.pop(k, None)
        HOST_RULES[k] = v
    for k, v in operator_rules["suffix"].items():
        SUFFIX_RULES.pop(k, None)
        SUFFIX_RULES[k] = v
    data = json.load(open(SRC))
    domains_out = []
    counts = {"BLOCK": 0, "OPTIONAL": 0, "REVIEW": 0, "SAFE": 0}
    cat_counts = {}
    blocklist = []
    for x in data["domains"]:
        host = x["domain"]
        rule, ev_list = classify(host)
        # quality control: BLOCK requires conf>=80 and breakage<30
        if rule["cls"] == "BLOCK" and not (rule["rk"]["breakage_risk"] < 30):
            rule = dict(rule)
            rule["cls"] = "REVIEW"
        counts[rule["cls"]] += 1
        for c in rule["cats"]:
            cat_counts[c] = cat_counts.get(c, 0) + 1
        if rule["cls"] == "BLOCK":
            blocklist.append(f"||{host}^")
        domains_out.append(to_domain_obj(host, rule, ev_list, x["queries"], x["clients"],
                                         x.get("whitelisted", False), x.get("first_seen_utc"), x.get("last_seen_utc")))

    def hi(key): return sum(1 for d in domains_out if d[key] >= 75)
    hard_blocks = sum(1 for d in domains_out if d["classification"] == "BLOCK" and d["decision_basis"]["hard_rules_triggered"])

    result = {
        "analysis_version": "3.0",
        "policy": "aggressive_privacy_safe",
        "meta": {
            "source": data["meta"]["source"],
            "method": data["meta"]["method"],
            "period_days": 30,
            "period_from_utc": data["meta"]["period_from_utc"],
            "generated_at_utc": data["meta"]["generated_at_utc"],
            "total_entries_scanned": data["meta"]["total_entries_scanned"],
            "allowed_entries": data["meta"]["allowed_entries"],
            "unique_allowed_domains": data["meta"]["unique_allowed_domains"],
            "reason_breakdown": {
                "NotFilteredNotFound": data["meta"]["reason_breakdown_raw_int"].get("none"),
                "FilteredBlackList": data["meta"]["reason_breakdown_raw_int"].get("3"),
                "NotFilteredWhiteList": data["meta"]["reason_breakdown_raw_int"].get("1"),
                "RewriteRule": data["meta"]["reason_breakdown_raw_int"].get("11"),
            },
            "clients_breakdown": data["meta"]["clients_breakdown"],
            "client_proto_breakdown": data["meta"]["client_proto_breakdown"],
            "classification_method": "known-service host rules -> suffix rules -> weak keywords -> REVIEW; external intel (RDAP/URLhaus) for the suspicious REVIEW subset",
            "external_api_keys_available": {"virustotal": False, "google_web_risk": False, "abuseipdb": False,
                                            "rdap": True, "urlhaus": True},
        },
        "summary": {
            "total_domains": len(domains_out),
            "block": counts["BLOCK"], "optional": counts["OPTIONAL"],
            "review": counts["REVIEW"], "safe": counts["SAFE"],
            "high_security_risk": hi("security_risk"), "high_privacy_risk": hi("privacy_risk"),
            "high_tracking_risk": hi("tracking_risk"), "hard_privacy_blocks": hard_blocks,
        },
        "category_breakdown": dict(sorted(cat_counts.items(), key=lambda kv: -kv[1])),
        "domains": domains_out,
        "final_blocklist": blocklist,
    }
    with open(OUT, "w") as f:
        json.dump(result, f, ensure_ascii=False, indent=1)
    print(json.dumps(result["summary"], ensure_ascii=False))
    print("review>=15 for enrichment:", sum(1 for d in domains_out if d["classification"] == "REVIEW" and d["queries_period"] >= 15))
    print(f"saved: {OUT}")


if __name__ == "__main__":
    main()
