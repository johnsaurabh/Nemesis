import tensorflow as tf
import aiohttp
import asyncio
from bs4 import BeautifulSoup
from typing import List, Dict
import re
from kafka import KafkaConsumer
from sklearn.feature_extraction import DictVectorizer
import logging

class Bloodhound:
    def __init__(self):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        self.model = tf.keras.models.load_model("malware_behavior.h5")
        self.c2_map: Dict[str, List[str]] = {}
        self.consumer = KafkaConsumer("pcap_stream", bootstrap_servers=["localhost:9092"])
        self.vectorizer = DictVectorizer()

    async def scrape_x_for_iocs(self) -> List[Dict[str, List[str]]]:
        async with aiohttp.ClientSession() as session:
            retries = 3
            for attempt in range(retries):
                try:
                    # Simulate X scraping (replace with real API)
                    async with session.get("http://example.com/x-posts", timeout=5) as resp:
                        if resp.status == 429:  # Rate limit
                            await asyncio.sleep(2 ** attempt)  # Exponential backoff
                            continue
                        if resp.status != 200:
                            self.logger.error(f"Failed to fetch X data: {resp.status}")
                            return []
                        soup = BeautifulSoup(await resp.text(), "html.parser")
                        return self.extract_iocs(soup)
                except asyncio.TimeoutError:
                    self.logger.warning(f"Timeout on attempt {attempt + 1}/{retries}")
                    if attempt == retries - 1:
                        return []
                    await asyncio.sleep(2 ** attempt)
        return []

    def extract_iocs(self, soup: BeautifulSoup) -> List[Dict[str, List[str]]]:
        iocs = []
        ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        domain_pattern = re.compile(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
        hash_pattern = re.compile(r"\b[a-fA-F0-9]{32,64}\b")  # MD5, SHA
        for text in soup.stripped_strings:
            ips = ip_pattern.findall(text)
            domains = domain_pattern.findall(text)
            hashes = hash_pattern.findall(text)
            if ips or domains or hashes:
                iocs.append({"ips": ips, "domains": domains, "hashes": hashes})
        return iocs

    async def analyze_traffic_stream(self):
        for message in self.consumer:
            try:
                pcap_data = message.value
                if len(pcap_data) > 10_000_000:  # 10MB limit
                    self.logger.warning("PCAP too large, processing in chunks")
                    pcap_data = pcap_data[:10_000_000]
                features = self.extract_pcap_features(pcap_data)
                prediction = self.model.predict([features])[0]
                if prediction > 0.9:
                    ip = features["src_ip"]
                    self.c2_map[ip] = self.c2_map.get(ip, []) + [features["domain"]]
                    self.logger.info(f"Detected C2: {ip} -> {features['domain']}")
                elif 0.5 <= prediction <= 0.9:
                    self.logger.info(f"Low confidence detection: {prediction}. Flagging for review.")
            except Exception as e:
                self.logger.error(f"Error processing PCAP: {e}")

    def extract_pcap_features(self, pcap_data: bytes) -> Dict[str, any]:
        # Placeholder: Replace with real PCAP parsing (e.g., scapy)
        return {"src_ip": "192.168.1.1", "dst_ip": "10.0.0.1", "packet_size": 1024, "domain": "evil.com"}

    async def run(self):
        iocs = await self.scrape_x_for_iocs()
        self.logger.info(f"Extracted IOCs: {iocs}")
        await self.analyze_traffic_stream()

if __name__ == "__main__":
    hound = Bloodhound()
    asyncio.run(hound.run())