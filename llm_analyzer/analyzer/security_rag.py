#!/usr/bin/env python3
"""
Security RAG (Retrieval-Augmented Generation)
Reusable RAG system for security log analysis
"""

import os
import json
import glob
import pickle
import sys
from typing import List, Dict, Tuple, Optional
import numpy as np

try:
    from sentence_transformers import SentenceTransformer
    import faiss
except ImportError as e:
    print(f"Missing required dependencies: {e}")
    print("Install with: pip install sentence-transformers faiss-cpu")
    sys.exit(1)


class SecurityRAG:
    """RAG system for security document analysis"""
   
    def __init__(self, embedding_model: str = "all-mpnet-base-v2"):
        print(f"Loading embedding model: {embedding_model}")
        try:
            self.embedding_model = SentenceTransformer(embedding_model)
            self.embedding_dimension = self.embedding_model.get_sentence_embedding_dimension()
        except Exception as e:
            print(f"Error loading embedding model: {e}")
            print("Falling back to smaller model...")
            try:
                self.embedding_model = SentenceTransformer("all-MiniLM-L6-v2")
                self.embedding_dimension = self.embedding_model.get_sentence_embedding_dimension()
                print("Loaded fallback model: all-MiniLM-L6-v2")
            except Exception as e2:
                print(f"Failed to load any embedding model: {e2}")
                raise
        
        self.index = faiss.IndexFlatIP(self.embedding_dimension)
        self.chunks = []
        self.metadata = []
        
    def chunk_json_document(self, content: str, filename: str, chunk_size: int = 1000, overlap: int = 200) -> List[Dict]:
        """Chunk JSON security documents"""
        chunks = []
        
        try:
            data = json.loads(content)
            
            # Process aggregations (most important for security analysis)
            if 'response' in data and 'aggregations' in data['response']:
                for agg_name, agg_data in data['response']['aggregations'].items():
                    chunk_text = f"Query: {filename}\nAggregation: {agg_name}\nData: {json.dumps(agg_data, indent=2)}"
                    chunks.append({
                        "text": chunk_text,
                        "filename": filename,
                        "section": f"aggregation_{agg_name}",
                        "type": "aggregation",
                        "importance": "high"
                    })
            
            # Process search hits (individual log entries)
            if 'response' in data and 'hits' in data['response']:
                hits = data['response']['hits']['hits']
                for i, hit in enumerate(hits):
                    chunk_text = f"Query: {filename}\nLog Entry {i+1}: {json.dumps(hit, indent=2)}"
                    chunks.append({
                        "text": chunk_text,
                        "filename": filename,
                        "section": f"hit_{i}",
                        "type": "hit",
                        "importance": "medium"
                    })
                
        except json.JSONDecodeError:
            # Fallback to text chunking for non-JSON files
            words = content.split()
            for i in range(0, len(words), chunk_size - overlap):
                chunk_words = words[i:i + chunk_size]
                chunk_text = " ".join(chunk_words)
                chunks.append({
                    "text": chunk_text,
                    "filename": filename,
                    "section": f"text_chunk_{i//chunk_size}",
                    "type": "text",
                    "importance": "medium"
                })
        except Exception as e:
            print(f"Warning: Error processing {filename}: {e}")
            chunks.append({
                "text": f"Raw content from {filename}:\n{content[:2000]}...",
                "filename": filename,
                "section": "raw_content",
                "type": "raw",
                "importance": "low"
            })
        
        return chunks
    
    def load_documents(self, directory: str, file_pattern: str = "*_result.json", recursive: bool = True) -> int:
        """Load and chunk documents from directory"""
        print(f"Scanning directory: {directory}")
        
        if not os.path.exists(directory):
            print(f"Directory does not exist: {directory}")
            return 0
        
        if recursive:
            pattern = os.path.join(directory, "**", file_pattern)
            files = glob.glob(pattern, recursive=True)
        else:
            pattern = os.path.join(directory, file_pattern)
            files = glob.glob(pattern)
        
        if not files:
            print(f"No files matching '{file_pattern}' found in {directory}")
            return 0
        
        print(f"Found {len(files)} files")
        
        all_chunks = []
        files_processed = 0
        files_skipped = 0
        
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    filename = os.path.basename(file_path)
                    relative_path = os.path.relpath(file_path, directory)
                    
                    if self._should_skip_file(content, filename):
                        files_skipped += 1
                        continue
                    
                    chunks = self.chunk_json_document(content, relative_path)
                    all_chunks.extend(chunks)
                    files_processed += 1
                    
            except UnicodeDecodeError:
                try:
                    with open(file_path, 'r', encoding='latin1') as f:
                        content = f.read()
                        chunks = self.chunk_json_document(content, os.path.relpath(file_path, directory))
                        all_chunks.extend(chunks)
                        files_processed += 1
                except Exception as e:
                    print(f"Error processing {file_path}: {e}")
                    files_skipped += 1
            except Exception as e:
                print(f"Error processing {file_path}: {e}")
                files_skipped += 1
        
        self.chunks = all_chunks
        print(f"Processed {files_processed} files, skipped {files_skipped}, {len(all_chunks)} chunks")
        return len(all_chunks)
    
    def _should_skip_file(self, content: str, filename: str) -> bool:
        """Determine if a file should be skipped"""
        try:
            if len(content.strip()) < 50:
                return True
            
            data = json.loads(content)
            
            if 'response' in data and 'hits' in data['response']:
                total_hits = data['response']['hits'].get('total', {})
                if isinstance(total_hits, dict):
                    hit_count = total_hits.get('value', 0)
                else:
                    hit_count = total_hits
                if hit_count == 0:
                    return True
            
            if 'response' in data and 'aggregations' in data['response']:
                aggregations = data['response']['aggregations']
                all_empty = True
                for agg_name, agg_data in aggregations.items():
                    if isinstance(agg_data, dict):
                        if 'buckets' in agg_data and agg_data['buckets']:
                            all_empty = False
                            break
                        if 'doc_count' in agg_data and agg_data['doc_count'] > 0:
                            all_empty = False
                            break
                        if 'value' in agg_data and agg_data['value'] > 0:
                            all_empty = False
                            break
                if all_empty:
                    return True
            
            return False
            
        except json.JSONDecodeError:
            return len(content.strip()) < 100
        except Exception:
            return False
    
    def build_index(self, cache_file: Optional[str] = None, force_rebuild: bool = False) -> bool:
        """Build FAISS vector index from loaded chunks"""
        if cache_file and os.path.exists(cache_file) and not force_rebuild:
            return self._load_cached_index(cache_file)
        
        if not self.chunks:
            print("No chunks available. Run load_documents first.")
            return False
        
        print(f"Creating embeddings for {len(self.chunks)} chunks...")
        texts = [chunk['text'] for chunk in self.chunks]
        
        try:
            embeddings = self.embedding_model.encode(texts, show_progress_bar=True)
        except Exception as e:
            print(f"Error creating embeddings: {e}")
            return False
        
        print("Building FAISS index...")
        try:
            self.index = faiss.IndexFlatIP(self.embedding_dimension)
            self.index.add(embeddings.astype('float32'))
        except Exception as e:
            print(f"Error building FAISS index: {e}")
            return False
        
        self.metadata = [{
            "filename": chunk['filename'], 
            "section": chunk['section'], 
            "type": chunk['type'],
            "importance": chunk.get('importance', 'medium')
        } for chunk in self.chunks]
        
        if cache_file:
            self._save_cached_index(cache_file, embeddings)
        
        print(f"Vector index built: {len(self.chunks)} chunks indexed")
        return True
    
    def _load_cached_index(self, cache_file: str) -> bool:
        """Load cached embeddings and rebuild index"""
        try:
            print(f"Loading cached embeddings from {cache_file}")
            with open(cache_file, 'rb') as f:
                cache_data = pickle.load(f)
                self.chunks = cache_data['chunks']
                self.metadata = cache_data['metadata']
                embeddings = cache_data['embeddings']
                
                self.index = faiss.IndexFlatIP(self.embedding_dimension)
                self.index.add(embeddings.astype('float32'))
                print(f"Loaded {len(self.chunks)} cached chunks")
                return True
        except Exception as e:
            print(f"Error loading cache: {e}")
            return False
    
    def _save_cached_index(self, cache_file: str, embeddings: np.ndarray):
        """Save embeddings to cache file"""
        try:
            cache_dir = os.path.dirname(cache_file)
            if cache_dir and not os.path.exists(cache_dir):
                os.makedirs(cache_dir, exist_ok=True)
            
            print(f"Caching embeddings to {cache_file}")
            with open(cache_file, 'wb') as f:
                pickle.dump({
                    'chunks': self.chunks,
                    'metadata': self.metadata,
                    'embeddings': embeddings
                }, f)
        except Exception as e:
            print(f"Error saving cache: {e}")
    
    def search(self, query: str, top_k: int = 10, importance_boost: Dict[str, float] = None) -> List[Tuple[str, float, Dict]]:
        """Search for relevant chunks using semantic similarity"""
        if len(self.chunks) == 0:
            return []
        
        try:
            query_embedding = self.embedding_model.encode([query])
            scores, indices = self.index.search(query_embedding.astype('float32'), min(top_k * 2, len(self.chunks)))
            
            if importance_boost is None:
                importance_boost = {"high": 1.2, "medium": 1.0, "low": 0.8}
            
            results = []
            for score, idx in zip(scores[0], indices[0]):
                if idx < len(self.chunks):
                    metadata = self.metadata[idx]
                    importance = metadata.get('importance', 'medium')
                    boosted_score = float(score) * importance_boost.get(importance, 1.0)
                    
                    results.append((
                        self.chunks[idx]['text'],
                        boosted_score,
                        metadata
                    ))
            
            results.sort(key=lambda x: x[1], reverse=True)
            return results[:top_k]
        
        except Exception as e:
            print(f"Error during search: {e}")
            return []
    
    def get_stats(self) -> Dict:
        """Get statistics about the loaded data"""
        if not self.chunks:
            return {"total_chunks": 0}
        
        stats = {
            "total_chunks": len(self.chunks),
            "files": len(set(chunk['filename'] for chunk in self.chunks)),
            "chunk_types": {},
            "importance_levels": {}
        }
        
        for chunk in self.chunks:
            chunk_type = chunk.get('type', 'unknown')
            importance = chunk.get('importance', 'unknown')
            stats["chunk_types"][chunk_type] = stats["chunk_types"].get(chunk_type, 0) + 1
            stats["importance_levels"][importance] = stats["importance_levels"].get(importance, 0) + 1
        
        return stats
    
    def clear(self):
        """Clear all data and reset the RAG system"""
        self.index = faiss.IndexFlatIP(self.embedding_dimension)
        self.chunks = []
        self.metadata = []
        print("RAG system cleared")
