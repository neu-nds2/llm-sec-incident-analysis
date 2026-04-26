#!/usr/bin/env python3
"""
Raw Log Extractor for Security Onion
Extracts ALL logs from a time range without any filtering
For use in experiments comparing filtered vs unfiltered LLM analysis
"""

import json
import os
import sys
import requests
from requests.auth import HTTPBasicAuth
import urllib3
from datetime import datetime
import argparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_INDEX = "logs-*"
DEFAULT_TIME_FIELD = "@timestamp"
REQUEST_TIMEOUT = 300


def load_config(env_file):
    """Load configuration from env file"""
    config = {}
    with open(env_file, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                config[key.strip()] = value.strip()
    return config


class RawLogExtractor:
    """Extract raw logs from Security Onion without filtering"""
    
    def __init__(self, host, username, password):
        self.host = host.rstrip('/')
        self.username = username
        self.password = password
        self.auth = HTTPBasicAuth(self.username, self.password)
        self.headers = {"Content-Type": "application/json"}
        
        print(f"🔧 Raw Log Extractor:")
        print(f"   Host: {self.host}")
        print(f"   User: {self.username}")
    
    def test_connection(self):
        """Test Elasticsearch connection"""
        try:
            test_query = {"query": {"match_all": {}}, "size": 0}
            response = requests.post(
                f"{self.host}/{DEFAULT_INDEX}/_search",
                auth=self.auth,
                headers=self.headers,
                json=test_query,
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                total_docs = result['hits']['total']['value']
                print(f"✅ Connected! Total documents: {total_docs:,}")
                return True
            else:
                print(f"❌ Connection failed: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Connection error: {e}")
            return False
    
    def get_log_count(self, start_date, end_date, index=DEFAULT_INDEX, time_field=DEFAULT_TIME_FIELD):
        """Get count of logs in time range"""
        query = {
            "query": {
                "range": {
                    time_field: {"gte": start_date, "lte": end_date}
                }
            },
            "size": 0
        }
        
        try:
            response = requests.post(
                f"{self.host}/{index}/_search",
                auth=self.auth,
                headers=self.headers,
                json=query,
                verify=False,
                timeout=REQUEST_TIMEOUT
            )
            
            if response.status_code == 200:
                return response.json()['hits']['total']['value']
            return 0
        except:
            return 0
    
    def extract_raw_logs(self, start_date, end_date, output_file, 
                         max_logs=10000, index=DEFAULT_INDEX, 
                         time_field=DEFAULT_TIME_FIELD, batch_size=1000):
        """Extract raw logs from a time range"""
        
        if len(start_date) == 10:
            start_date = f"{start_date}T00:00:00"
        if len(end_date) == 10:
            end_date = f"{end_date}T23:59:59"
        
        print(f"\n📥 Extracting logs:")
        print(f"   Range: {start_date} to {end_date}")
        print(f"   Max: {max_logs:,}")
        
        total_available = self.get_log_count(start_date, end_date, index, time_field)
        print(f"   Available: {total_available:,}")
        
        if total_available == 0:
            print("⚠️  No logs found!")
            return 0
        
        all_logs = []
        extracted = 0
        
        query = {
            "query": {
                "range": {
                    time_field: {"gte": start_date, "lte": end_date}
                }
            },
            "size": min(batch_size, max_logs),
            "sort": [{time_field: "asc"}]
        }
        
        try:
            response = requests.post(
                f"{self.host}/{index}/_search?scroll=5m",
                auth=self.auth,
                headers=self.headers,
                json=query,
                verify=False,
                timeout=REQUEST_TIMEOUT
            )
            
            if response.status_code != 200:
                print(f"❌ Search failed: {response.status_code}")
                return 0
            
            result = response.json()
            scroll_id = result.get('_scroll_id')
            hits = result['hits']['hits']
            
            while hits and extracted < max_logs:
                for hit in hits:
                    if extracted >= max_logs:
                        break
                    all_logs.append({
                        "_id": hit['_id'],
                        "_index": hit['_index'],
                        "_source": hit['_source']
                    })
                    extracted += 1
                
                if extracted % 1000 == 0:
                    print(f"   📊 Extracted: {extracted:,}")
                
                if extracted >= max_logs:
                    break
                
                scroll_response = requests.post(
                    f"{self.host}/_search/scroll",
                    auth=self.auth,
                    headers=self.headers,
                    json={"scroll": "5m", "scroll_id": scroll_id},
                    verify=False,
                    timeout=REQUEST_TIMEOUT
                )
                
                if scroll_response.status_code != 200:
                    break
                
                scroll_result = scroll_response.json()
                hits = scroll_result['hits']['hits']
                scroll_id = scroll_result.get('_scroll_id', scroll_id)
            
            # Clear scroll
            try:
                requests.delete(
                    f"{self.host}/_search/scroll",
                    auth=self.auth,
                    headers=self.headers,
                    json={"scroll_id": scroll_id},
                    verify=False,
                    timeout=10
                )
            except:
                pass
            
        except Exception as e:
            print(f"❌ Error: {e}")
        
        if all_logs:
            output_data = {
                "metadata": {
                    "extraction_type": "raw_unfiltered",
                    "start_date": start_date,
                    "end_date": end_date,
                    "index": index,
                    "total_available": total_available,
                    "total_extracted": len(all_logs),
                    "extraction_time": datetime.now().isoformat()
                },
                "logs": all_logs
            }
            
            output_dir = os.path.dirname(output_file)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir, exist_ok=True)
            
            with open(output_file, 'w') as f:
                json.dump(output_data, f, indent=2, default=str)
            
            size_mb = os.path.getsize(output_file) / (1024 * 1024)
            
            print(f"\n✅ Extracted {len(all_logs):,} logs")
            print(f"   📁 Output: {output_file}")
            print(f"   💾 Size: {size_mb:.2f} MB")
            
            return len(all_logs)
        
        return 0
    
    def list_indices(self):
        """List available indices"""
        try:
            response = requests.get(
                f"{self.host}/_cat/indices?format=json",
                auth=self.auth,
                verify=False,
                timeout=30
            )
            
            if response.status_code == 200:
                indices = response.json()
                print(f"\n📋 Indices ({len(indices)}):")
                for idx in sorted(indices, key=lambda x: x['index'])[:20]:
                    if not idx['index'].startswith('.'):
                        print(f"   {idx['index']}: {idx.get('docs.count', 0)} docs")
                return True
            return False
        except Exception as e:
            print(f"❌ Error: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(
        description="Extract raw logs from Elasticsearch",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python raw_log_extractor.py --env env.so --test
  python raw_log_extractor.py --env env.so --list-indices
  python raw_log_extractor.py --env env.so --start-date 2025-01-22 --end-date 2025-01-22 -o raw.json
        """
    )
    
    parser.add_argument("--env", required=True, help="Environment file with credentials")
    parser.add_argument("--test", action="store_true", help="Test connection")
    parser.add_argument("--list-indices", action="store_true", help="List indices")
    parser.add_argument("--start-date", help="Start date (YYYY-MM-DD)")
    parser.add_argument("--end-date", help="End date (YYYY-MM-DD)")
    parser.add_argument("--output", "-o", help="Output file")
    parser.add_argument("--max-logs", type=int, default=10000, help="Max logs (default: 10000)")
    parser.add_argument("--index", default=DEFAULT_INDEX, help="Index pattern")
    
    args = parser.parse_args()
    
    # Load config
    if not os.path.exists(args.env):
        print(f"❌ Env file not found: {args.env}")
        sys.exit(1)
    
    config = load_config(args.env)
    print(f"📁 Loaded: {args.env}")
    
    host = config.get('ELASTICSEARCH_HOST', 'https://localhost:9200')
    username = config.get('ELASTICSEARCH_USERNAME', '')
    password = config.get('ELASTICSEARCH_PASSWORD', '')
    
    extractor = RawLogExtractor(host, username, password)
    
    if args.test:
        extractor.test_connection()
        return
    
    if args.list_indices:
        extractor.list_indices()
        return
    
    if not args.start_date or not args.end_date:
        print("❌ --start-date and --end-date required")
        sys.exit(1)
    
    if not args.output:
        args.output = f"raw_logs_{args.start_date}_{args.end_date}.json"
    
    if not extractor.test_connection():
        sys.exit(1)
    
    count = extractor.extract_raw_logs(
        start_date=args.start_date,
        end_date=args.end_date,
        output_file=args.output,
        max_logs=args.max_logs,
        index=args.index
    )
    
    if count > 0:
        print(f"\n💡 Next: python raw_to_analyzer_format.py {args.output} output_dir/")
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
