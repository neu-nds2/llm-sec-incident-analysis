#!/usr/bin/env python3
"""
Raw Logs to Analyzer Format Converter
Converts extracted raw logs into the format expected by the security analyzer

The existing analyzer expects files in this format:
{
    "metadata": {...},
    "query": {...},
    "response": {
        "hits": {"total": {"value": N}, "hits": [...]},
        "aggregations": {...}
    },
    "success": true
}

This script converts raw log extractions into that format,
splitting large files into manageable chunks for the RAG system.
"""

import json
import os
import sys
import argparse
from datetime import datetime
from typing import List, Dict, Any

def load_raw_logs(input_file: str) -> Dict[str, Any]:
    """Load raw logs from extraction file"""
    print(f"📂 Loading raw logs from: {input_file}")
    
    with open(input_file, 'r') as f:
        data = json.load(f)
    
    logs = data.get('logs', [])
    metadata = data.get('metadata', {})
    
    print(f"   📊 Loaded {len(logs):,} log entries")
    print(f"   📅 Time range: {metadata.get('start_date')} to {metadata.get('end_date')}")
    
    return data


def convert_to_analyzer_format(raw_data: Dict[str, Any], 
                               output_dir: str,
                               logs_per_file: int = 500,
                               create_aggregations: bool = True) -> int:
    """
    Convert raw logs to analyzer-expected format
    
    Args:
        raw_data: Raw log extraction data
        output_dir: Directory to save converted files
        logs_per_file: Number of logs per output file
        create_aggregations: Whether to compute basic aggregations
    
    Returns:
        Number of files created
    """
    
    logs = raw_data.get('logs', [])
    metadata = raw_data.get('metadata', {})
    
    if not logs:
        print("❌ No logs to convert!")
        return 0
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Split logs into chunks
    chunks = [logs[i:i + logs_per_file] for i in range(0, len(logs), logs_per_file)]
    
    print(f"\n📦 Converting {len(logs):,} logs into {len(chunks)} files...")
    
    files_created = 0
    
    for chunk_idx, chunk_logs in enumerate(chunks):
        # Prepare hits in expected format
        hits = []
        for log in chunk_logs:
            hit = {
                "_index": log.get('_index', 'unknown'),
                "_id": log.get('_id', ''),
                "_source": log.get('_source', log)
            }
            hits.append(hit)
        
        # Create the result structure expected by the analyzer
        result_data = {
            "metadata": {
                "query_file": f"raw_logs_chunk_{chunk_idx:03d}.json",
                "execution_time": datetime.now().isoformat(),
                "source": "raw_extraction",
                "original_file": metadata.get('extraction_time', 'unknown'),
                "time_range": {
                    "start": metadata.get('start_date'),
                    "end": metadata.get('end_date')
                },
                "chunk_info": {
                    "chunk_number": chunk_idx + 1,
                    "total_chunks": len(chunks),
                    "logs_in_chunk": len(chunk_logs),
                    "total_logs": len(logs)
                }
            },
            "query": {
                "query": {"match_all": {}},
                "description": f"Raw unfiltered logs chunk {chunk_idx + 1}/{len(chunks)}"
            },
            "response": {
                "took": 0,
                "hits": {
                    "total": {
                        "value": len(chunk_logs),
                        "relation": "eq"
                    },
                    "hits": hits
                }
            },
            "success": True
        }
        
        # Add aggregations if requested (computed from this chunk)
        if create_aggregations:
            aggregations = compute_basic_aggregations(chunk_logs)
            if aggregations:
                result_data["response"]["aggregations"] = aggregations
        
        # Save the file
        output_file = os.path.join(output_dir, f"raw_logs_chunk_{chunk_idx:03d}_result.json")
        with open(output_file, 'w') as f:
            json.dump(result_data, f, indent=2, default=str)
        
        files_created += 1
        
        if (chunk_idx + 1) % 10 == 0:
            print(f"   ✅ Created {files_created}/{len(chunks)} files...")
    
    print(f"\n✅ Conversion complete!")
    print(f"   📁 Output directory: {output_dir}")
    print(f"   📄 Files created: {files_created}")
    
    return files_created


def compute_basic_aggregations(logs: List[Dict]) -> Dict[str, Any]:
    """
    Compute basic aggregations from raw logs to help with analysis
    
    Looks for common security-relevant fields and creates aggregations
    """
    aggregations = {}
    
    # Field counters
    field_counters = {
        'source_ip': {},
        'dest_ip': {},
        'source.ip': {},
        'destination.ip': {},
        'src_ip': {},
        'dst_ip': {},
        'event.action': {},
        'event.category': {},
        'event.type': {},
        'rule.name': {},
        'agent.name': {},
        'host.name': {},
        'user.name': {},
        'process.name': {},
        'network.protocol': {},
        'destination.port': {},
        'source.port': {},
    }
    
    # Process each log
    for log in logs:
        source = log.get('_source', log)
        
        # Flatten nested fields for counting
        flat_source = flatten_dict(source)
        
        for field_name, counter in field_counters.items():
            value = flat_source.get(field_name)
            if value is not None:
                str_value = str(value)
                counter[str_value] = counter.get(str_value, 0) + 1
    
    # Convert counters to aggregation format (top 20 values)
    for field_name, counter in field_counters.items():
        if counter:
            # Sort by count and take top 20
            sorted_items = sorted(counter.items(), key=lambda x: x[1], reverse=True)[:20]
            
            buckets = [
                {"key": key, "doc_count": count}
                for key, count in sorted_items
            ]
            
            # Use underscore format for aggregation names
            agg_name = field_name.replace('.', '_') + "_agg"
            aggregations[agg_name] = {
                "buckets": buckets,
                "doc_count_error_upper_bound": 0,
                "sum_other_doc_count": sum(counter.values()) - sum(c for _, c in sorted_items)
            }
    
    return aggregations


def flatten_dict(d: Dict, parent_key: str = '', sep: str = '.') -> Dict:
    """Flatten nested dictionary"""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def create_summary_file(raw_data: Dict[str, Any], output_dir: str):
    """Create a summary file with statistics about the raw logs"""
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    logs = raw_data.get('logs', [])
    metadata = raw_data.get('metadata', {})
    
    # Compute statistics
    all_fields = set()
    index_counts = {}
    
    for log in logs:
        # Track indices
        idx = log.get('_index', 'unknown')
        index_counts[idx] = index_counts.get(idx, 0) + 1
        
        # Track fields
        source = log.get('_source', log)
        flat = flatten_dict(source)
        all_fields.update(flat.keys())
    
    # Get timestamp range from logs
    timestamps = []
    for log in logs:
        source = log.get('_source', log)
        ts = source.get('@timestamp') or source.get('timestamp')
        if ts:
            timestamps.append(ts)
    
    timestamps.sort()
    
    summary = {
        "extraction_metadata": metadata,
        "statistics": {
            "total_logs": len(logs),
            "unique_indices": len(index_counts),
            "unique_fields": len(all_fields),
            "index_distribution": dict(sorted(index_counts.items(), key=lambda x: x[1], reverse=True)[:20]),
            "timestamp_range": {
                "earliest": timestamps[0] if timestamps else None,
                "latest": timestamps[-1] if timestamps else None
            }
        },
        "available_fields": sorted(list(all_fields))[:100],  # Top 100 fields
        "analysis_notes": {
            "description": "Raw unfiltered logs extracted for LLM analysis experiment",
            "comparison_purpose": "Compare LLM performance on raw vs. filtered/queried data",
            "recommendations": [
                "Review index_distribution to understand log types",
                "Check available_fields to identify relevant security fields",
                "Consider filtering by specific indices if data is too noisy"
            ]
        }
    }
    
    summary_file = os.path.join(output_dir, "extraction_summary.json")
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2, default=str)
    
    print(f"\n📋 Summary saved to: {summary_file}")
    print(f"   📊 Total logs: {len(logs):,}")
    print(f"   📁 Indices: {len(index_counts)}")
    print(f"   📝 Unique fields: {len(all_fields)}")
    
    if timestamps:
        print(f"   ⏰ Time range: {timestamps[0]} to {timestamps[-1]}")
    
    return summary


def main():
    parser = argparse.ArgumentParser(
        description="Convert raw log extractions to analyzer format",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic conversion
  python3 raw_to_analyzer_format.py raw_logs.json output_dir/
  
  # Specify logs per file
  python3 raw_to_analyzer_format.py raw_logs.json output_dir/ --logs-per-file 1000
  
  # Skip aggregation computation
  python3 raw_to_analyzer_format.py raw_logs.json output_dir/ --no-aggregations
  
  # Create summary only
  python3 raw_to_analyzer_format.py raw_logs.json output_dir/ --summary-only
        """
    )
    
    parser.add_argument("input_file", help="Raw log extraction JSON file")
    parser.add_argument("output_dir", help="Output directory for converted files")
    parser.add_argument("--logs-per-file", type=int, default=500, 
                        help="Number of logs per output file (default: 500)")
    parser.add_argument("--no-aggregations", action="store_true",
                        help="Skip computing aggregations")
    parser.add_argument("--summary-only", action="store_true",
                        help="Only create summary file, don't convert logs")
    
    args = parser.parse_args()
    
    # Validate input
    if not os.path.exists(args.input_file):
        print(f"❌ Input file not found: {args.input_file}")
        sys.exit(1)
    
    # Load raw logs
    raw_data = load_raw_logs(args.input_file)
    
    # Create summary
    create_summary_file(raw_data, args.output_dir)
    
    if args.summary_only:
        print("\n✅ Summary created (--summary-only mode)")
        return
    
    # Convert to analyzer format
    files_created = convert_to_analyzer_format(
        raw_data,
        args.output_dir,
        logs_per_file=args.logs_per_file,
        create_aggregations=not args.no_aggregations
    )
    
    if files_created > 0:
        print(f"\n🎉 Ready for analysis!")
        print(f"\n💡 Run analysis with:")
        print(f"   python3 ../llm_analyzer/analyze.py {args.output_dir} \\")
        print(f"       --provider anthropic \\")
        print(f"       --api-key-file keys/anthropic.txt \\")
        print(f"       --cache cache/raw_logs_embeddings.pkl \\")
        print(f"       --network-file config/network.txt \\")
        print(f"       --questions-file config/questions.txt \\")
        print(f"       --output reports/raw_logs_analysis.md")


if __name__ == "__main__":
    main()
