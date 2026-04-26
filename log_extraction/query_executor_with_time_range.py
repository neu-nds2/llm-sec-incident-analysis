#!/usr/bin/env python3
"""
Elasticsearch Query Executor with Time Range Filtering
Executes queries against Security Onion / ELK Stack
"""

import json
import sys
import os
import glob
import requests
from requests.auth import HTTPBasicAuth
import urllib3
from datetime import datetime
import argparse
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Defaults (can be overridden by env file or command line)
DEFAULT_INDEX = "logs-*"
DEFAULT_TIME_FIELD = "@timestamp"
REQUEST_TIMEOUT = 300

# =============================================================================
# QUERY EXECUTOR
# =============================================================================

def parse_time_range(start_date, end_date, time_field=DEFAULT_TIME_FIELD):
    """Parse start and end dates into Elasticsearch format"""
    time_range = {"field": time_field}
    
    if start_date:
        if re.match(r'^\d{4}-\d{2}-\d{2}$', start_date):
            time_range["gte"] = f"{start_date}T00:00:00"
        else:
            time_range["gte"] = start_date
    else:
        time_range["gte"] = "1970-01-01T00:00:00"
    
    if end_date:
        if re.match(r'^\d{4}-\d{2}-\d{2}$', end_date):
            time_range["lte"] = f"{end_date}T23:59:59"
        else:
            time_range["lte"] = end_date
    else:
        time_range["lte"] = "2030-12-31T23:59:59"
    
    return time_range


class QueryExecutor:
    """Execute Elasticsearch queries with time range filtering"""
    
    def __init__(self, host, username, password, time_range=None):
        self.host = host
        self.username = username
        self.password = password
        self.auth = HTTPBasicAuth(self.username, self.password)
        self.headers = {"Content-Type": "application/json"}
        self.time_range = time_range
        
        print(f"🔧 Elasticsearch: {self.host}")
        if self.time_range:
            print(f"📅 Time range: {self.time_range['gte']} to {self.time_range['lte']}")
    
    def apply_time_filter(self, query_data):
        """Apply time range filter to query"""
        if not self.time_range:
            return query_data
        
        modified_query = query_data.copy()
        time_filter = {
            "range": {
                self.time_range["field"]: {
                    "gte": self.time_range["gte"],
                    "lte": self.time_range["lte"]
                }
            }
        }
        
        if "query" not in modified_query:
            modified_query["query"] = {"match_all": {}}
        
        original_query = modified_query["query"]
        
        if isinstance(original_query, dict) and "bool" in original_query:
            if "must" not in original_query["bool"]:
                original_query["bool"]["must"] = []
            elif not isinstance(original_query["bool"]["must"], list):
                original_query["bool"]["must"] = [original_query["bool"]["must"]]
            original_query["bool"]["must"].append(time_filter)
        else:
            modified_query["query"] = {
                "bool": {"must": [original_query, time_filter]}
            }
        
        return modified_query
    
    def execute_query_file(self, query_file, output_file):
        """Execute a single query file"""
        print(f"  📄 {os.path.basename(query_file)}", end=" ")
        
        try:
            with open(query_file, 'r') as f:
                query_data = json.load(f)
            
            index = query_data.pop('index', DEFAULT_INDEX)
            if self.time_range:
                query_data = self.apply_time_filter(query_data)
            
            start_time = datetime.now()
            response = requests.post(
                f"{self.host}/{index}/_search",
                auth=self.auth, headers=self.headers,
                json=query_data, verify=False, timeout=REQUEST_TIMEOUT
            )
            duration_ms = (datetime.now() - start_time).total_seconds() * 1000
            
            result_data = {
                "metadata": {
                    "query_file": os.path.basename(query_file),
                    "execution_time": start_time.isoformat(),
                    "status_code": response.status_code,
                    "duration_ms": duration_ms,
                    "index": index,
                    "time_range": self.time_range
                },
                "query": query_data,
                "response": None,
                "success": False
            }
            
            if response.status_code == 200:
                es_result = response.json()
                result_data["response"] = es_result
                result_data["success"] = True
                total_hits = es_result['hits']['total']['value']
                print(f"→ {total_hits:,} hits ({duration_ms:.0f}ms)")
            else:
                result_data["response"] = {"error": response.text[:200]}
                print(f"→ ❌ HTTP {response.status_code}")
            
            with open(output_file, 'w') as f:
                json.dump(result_data, f, indent=2, default=str)
            
            return result_data["success"]
            
        except Exception as e:
            print(f"→ ❌ {e}")
            return False
    
    def process_directory(self, input_dir, output_dir, file_pattern="*.json"):
        """Process all query files in directory"""
        os.makedirs(output_dir, exist_ok=True)
        query_files = sorted(glob.glob(os.path.join(input_dir, file_pattern)))
        
        if not query_files:
            print(f"❌ No queries found: {input_dir}/{file_pattern}")
            return False
        
        print(f"\n🚀 Running {len(query_files)} queries → {output_dir}")
        
        success = 0
        for qf in query_files:
            out = os.path.join(output_dir, f"{os.path.splitext(os.path.basename(qf))[0]}_result.json")
            if self.execute_query_file(qf, out):
                success += 1
        
        print(f"\n✅ {success}/{len(query_files)} queries successful")
        return success == len(query_files)
    
    def test_connection(self):
        """Test Elasticsearch connection"""
        try:
            response = requests.post(
                f"{self.host}/{DEFAULT_INDEX}/_search",
                auth=self.auth, headers=self.headers,
                json={"query": {"match_all": {}}, "size": 0},
                verify=False, timeout=10
            )
            if response.status_code == 200:
                total = response.json()['hits']['total']['value']
                print(f"✅ Connected: {total:,} documents")
                return True
            print(f"❌ HTTP {response.status_code}")
            return False
        except Exception as e:
            print(f"❌ {e}")
            return False


def load_config(env_file=None):
    """Load configuration from env file"""
    from dotenv import load_dotenv
    
    if env_file:
        if not os.path.exists(env_file):
            print(f"❌ Env file not found: {env_file}")
            sys.exit(1)
        load_dotenv(env_file)
        print(f"📁 Loaded: {env_file}")
    
    host = os.getenv('ELASTICSEARCH_HOST')
    username = os.getenv('ELASTICSEARCH_USERNAME')
    password = os.getenv('ELASTICSEARCH_PASSWORD')
    
    if not all([host, username, password]):
        print("❌ Missing credentials. Set via --env file or environment variables:")
        print("   ELASTICSEARCH_HOST, ELASTICSEARCH_USERNAME, ELASTICSEARCH_PASSWORD")
        sys.exit(1)
    
    return host, username, password


def main():
    parser = argparse.ArgumentParser(
        description="Execute Elasticsearch queries with time filtering",
        epilog="Example: %(prog)s queries/ output/ --env env.so --start-date 2025-01-22 --end-date 2025-01-22"
    )
    
    parser.add_argument("input_dir", nargs='?', help="Query directory")
    parser.add_argument("output_dir", nargs='?', help="Output directory")
    parser.add_argument("--env", required=True, help="Environment file with credentials (e.g., env.so)")
    parser.add_argument("--start-date", help="Start date (YYYY-MM-DD)")
    parser.add_argument("--end-date", help="End date (YYYY-MM-DD)")
    parser.add_argument("--test", action="store_true", help="Test connection only")
    
    args = parser.parse_args()
    
    # Load credentials from env file
    host, username, password = load_config(args.env)
    
    time_range = parse_time_range(args.start_date, args.end_date) if args.start_date or args.end_date else None
    executor = QueryExecutor(host, username, password, time_range)
    
    if args.test:
        sys.exit(0 if executor.test_connection() else 1)
    
    if not args.input_dir or not args.output_dir:
        parser.print_help()
        sys.exit(1)
    
    executor.test_connection()
    sys.exit(0 if executor.process_directory(args.input_dir, args.output_dir) else 1)


if __name__ == "__main__":
    main()
