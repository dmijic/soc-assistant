from fastapi import FastAPI, HTTPException
from app.log_parser import parse_file
from app.analyzer import analyze
from app.config import settings
from app.vector_store import find_similar, get_collection
from app.ollama_client import OllamaClient

app = FastAPI()

@app.get("/")
def root():
    return {"status": "ok"}


@app.get("/health")
def health_check():
    return {"status": "healthy"}

@app.post("/analyze")
def analyze_logs(log_path: str = None):
    try:
        if log_path is None:
            log_path = settings.log_path
        entries = parse_file(log_path)
        reports = analyze(entries)
        return {"reports": [report.model_dump() for report in reports]}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Log file not found: {log_path}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to analyze logs: {str(e)}")


@app.get("/reports")
def get_reports():
    try:
        collection = get_collection()
        results = collection.get()
        return {"reports": results['metadatas']}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve reports: {str(e)}")


@app.post("/search")
def search_reports(query: str, n: int = 3):
    try:
        client = OllamaClient(base_url=settings.ollama_base_url)
        results = find_similar(query=query, client=client, model=settings.ollama_embed_model, n=n)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to search reports: {str(e)}")
    return {"reports": results}
