from abc import ABC, abstractmethod
import os
import httpx

class AiProvider(ABC):
    """
    Abstract Base Class for AI Exposure Intelligence analysis.
    """
    @abstractmethod
    async def analyze_findings(self, prompt: str) -> str:
        pass


class GeminiProvider(AiProvider):
    """
    Gemini API client using REST requests to model gemini-2.5-flash.
    """
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={self.api_key}"

    async def analyze_findings(self, prompt: str) -> str:
        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": prompt}
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.2,
                "topK": 40,
                "topP": 0.95,
                "maxOutputTokens": 2048,
            }
        }
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(self.api_url, json=payload)
                if response.status_code == 200:
                    data = response.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                        if text:
                            return text
                    return "Error: Empty text response from Gemini."
                else:
                    return f"Error: Gemini API returned status code {response.status_code}. Response: {response.text}"
        except Exception as e:
            return f"Error connecting to Gemini API: {str(e)}"


class FallbackRuleProvider(AiProvider):
    """
    Fallback provider using rule-based templates if no API key is set.
    """
    async def analyze_findings(self, prompt: str) -> str:
        # Simplistic rule-based template fallback
        return (
            "### AI Exposure Intelligence Report (Fallback)\n\n"
            "**Executive Summary:**\n"
            "Analysis of provided vulnerabilities indicates potential privilege escalation vectors on exposed API boundaries. "
            "Remediation effort is classified as Medium.\n\n"
            "**Key Recommendations:**\n"
            "1. Enforce strict ownership validation (BOLA checks) on path-segment identifiers.\n"
            "2. Implement allowlist DNS checks on outbound server-side requests (SSRF defense)."
        )


def get_provider() -> AiProvider:
    """
    Factory function to retrieve configured AI provider.
    """
    # Try fetching GEMINI_API_KEY from environment or settings
    api_key = os.getenv("GEMINI_API_KEY")
    if api_key:
        return GeminiProvider(api_key)
    
    return FallbackRuleProvider()
