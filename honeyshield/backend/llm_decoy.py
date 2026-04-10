import os
import json
import logging
from openai import OpenAI

logger = logging.getLogger(__name__)

# System prompt tuned to generate very structured JSON decoys
SYSTEM_PROMPT = """You are an advanced honeypot decoy generation engine. Your purpose is to create hyper-realistic, fake data intended to deceive attackers. You MUST return ONLY valid JSON matching the requested structure. Do not output markdown code blocks (like ```json), just the raw JSON text. Make the data look like it belongs to a corporate internal tool (e.g. 'NexusCorp')."""

class FeatherlessDecoyGenerator:
    def __init__(self):
        from dotenv import load_dotenv
        # Ensure we load .env from honeyshield/
        load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))
        api_key = os.environ.get("FEATHERLESS_API_KEY")
        
        if not api_key:
            logger.warning("No FEATHERLESS_API_KEY found in environment!")
            self.client = None
        else:
            self.client = OpenAI(
                api_key=api_key,
                base_url="https://api.featherless.ai/v1"
            )
        
        self.model = "zai-org/GLM-5"

    def is_configured(self):
        return self.client is not None

    def generate_decoy(self, decoy_type: str) -> dict:
        """
        Generate fake data based on the requested type.
        """
        if not self.is_configured():
            return {"error": "LLM not configured (missing FEATHERLESS_API_KEY)"}

        prompt_map = {
            "network_logs": "Generate 8 realistic active access logs. Format as a JSON list of objects with fields: timestamp (HH:MM:SS), service (e.g., SSH, VPN, Kube API, internal DB), ip (random internal 10.x.x.x IPs), status (GRANTED, CHALLENGE, or DENY), status_color (bg-green, bg-yellow, bg-red).",
            "telemetry": "Generate 3 fake telemetry stats for a dashboard. Format as a JSON object with keys: active_connections (number around 1500), cpu_load (percentage string like 42%), firewall_drops (number around 90).",
            "db_dump": "Generate 5 fake employee records for a data leak bait file. JSON list of objects with fields: id, name, email, department, salary, role, ssh_key_snippet (short base64 string).",
            "config": "Generate a fake config.json containing dummy AWS keys, database URIs, and a master API token."
        }

        user_prompt = prompt_map.get(decoy_type)
        if not user_prompt:
            return {"error": f"Unknown decoy type: {decoy_type}"}

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.7, # A bit of creativity for realistic logs
            )
            
            content = response.choices[0].message.content.strip()
            # In case the model accidentally replies with markdown
            if content.startswith("```json"):
                content = content[7:]
            if content.startswith("```"):
                content = content[3:]
            if content.endswith("```"):
                content = content[:-3]
                
            return json.loads(content.strip())
            
        except Exception as e:
            logger.error(f"Failed to generate decoy via GLM-5: {str(e)}")
            return {"error": str(e)}

# Singleton instance
decoy_generator = FeatherlessDecoyGenerator()
