import chromadb
from app.analyzer import AnomalyReport
from app.ollama_client import OllamaClient

COLLECTION_NAME = "anomaly_reports"

def get_collection() -> chromadb.Collection:
    client = chromadb.PersistentClient(path="data/chroma")
    return client.get_or_create_collection(COLLECTION_NAME)

def add_report(report: AnomalyReport, client: OllamaClient, model: str) -> None:
    text = f"{report.type} {report.severity} {report.description} {' '.join(report.examples)}"
    embedding = client.embed(model=model, text=text)
    collection = get_collection()
    collection.add(
        documents=[text],
        metadatas=[report.model_dump()],
        ids=[f"{report.type}_{report.source_ip}"],
        embeddings=[embedding]
    )

def find_similar(query: str, client: OllamaClient, model: str, n: int = 3) -> list[dict]:
    embedding = client.embed(model=model, text=query)
    collection = get_collection()
    results = collection.query(
        query_embeddings=[embedding],
        n_results=n
    )
    similar_reports = []
    for doc, metadata in zip(results['documents'][0], results['metadatas'][0]):
        similar_reports.append({
            "document": doc,
            "metadata": metadata
        })
    return similar_reports
