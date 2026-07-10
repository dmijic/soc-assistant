import httpx

class OllamaClient():
    def __init__(self, base_url: str):
        self.base_url = base_url

    def embed(self, model: str, text: str) -> list[float]:
        response = httpx.post(
            f"{self.base_url}/api/embeddings",
            json={
                "model": model,
                "prompt": text
            },
            timeout=120
        )
        data = response.json()
        return data["embedding"]

    def generate(self, model: str, prompt: str) -> str:
        response = httpx.post(
            f"{self.base_url}/api/generate",
            json={
                "model": model,
                "prompt": prompt,
                "stream": False
            },
            timeout=120
        )
        data = response.json()
        return data["response"]