#!/usr/bin/env python3
"""Integration tests for JSONL output from various tracers."""

import json
import os
import subprocess
import tempfile
import sys
from pathlib import Path

# Add parent directory to path for test utilities
sys.path.insert(0, str(Path(__file__).parent.parent))

def run_tracer(tracer_name, config_args, target_binary, build_dir):
    """Run a tracer and return the output file path."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
        output_file = f.name
    
    cmd = [
        os.path.join(build_dir, 'w1tool'),
        'tracer',
        '-n', tracer_name,
        '-c', f'output={output_file}'
    ]
    
    # Add additional config arguments
    for key, value in config_args.items():
        cmd.extend(['-c', f'{key}={value}'])
    
    cmd.extend(['-s', target_binary])
    
    # Run the tracer
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error running {tracer_name}:")
        print(f"stdout: {result.stdout}")
        print(f"stderr: {result.stderr}")
        raise RuntimeError(f"Tracer {tracer_name} failed with code {result.returncode}")
    
    return output_file

def validate_jsonl_format(file_path):
    """Validate that the file is proper JSONL format."""
    line_count = 0
    with open(file_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            
            try:
                json.loads(line)
                line_count += 1
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON on line {line_num}: {e}\nLine: {line}")
    
    return line_count

def parse_jsonl_file(file_path):
    """Parse JSONL file and return metadata and events."""
    metadata = None
    events = []
    
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            obj = json.loads(line)
            if obj.get('type') == 'metadata':
                metadata = obj
            elif obj.get('type') == 'event':
                events.append(obj)
    
    return metadata, events

def test_w1xfer_jsonl(build_dir, target_binary):
    """Test w1xfer tracer JSONL output."""
    print("Testing w1xfer JSONL output...")
    
    output_file = run_tracer('w1xfer', {'analyze_apis': 'true'}, target_binary, build_dir)
    
    try:
        # Validate format
        line_count = validate_jsonl_format(output_file)
        print(f"  ✓ Valid JSONL format ({line_count} lines)")
        
        # Parse content
        metadata, events = parse_jsonl_file(output_file)
        
        # Check metadata
        assert metadata is not None, "No metadata found"
        assert metadata['tracer'] == 'w1xfer', f"Wrong tracer in metadata: {metadata.get('tracer')}"
        assert 'modules' in metadata, "No modules in metadata"
        assert len(metadata['modules']) > 0, "No modules listed"
        print(f"  ✓ Valid metadata with {len(metadata['modules'])} modules")
        
        # Check events
        assert len(events) > 0, "No events found"
        
        # Verify event structure
        event = events[0]
        assert 'data' in event, "No data in event"
        data = event['data']
        
        # Check required fields for transfer entry (no timestamp)
        required_fields = ['type', 'source_address', 'target_address', 'instruction_count']
        for field in required_fields:
            assert field in data, f"Missing field '{field}' in event data"
        
        print(f"  ✓ Valid events ({len(events)} transfers captured)")
        
    finally:
        os.unlink(output_file)

def test_w1inst_jsonl(build_dir, target_binary):
    """Test w1inst tracer JSONL output."""
    print("Testing w1inst JSONL output...")
    
    mnemonics = 'B,BL,BR,BLR,RET,BLRAA,BLRAB,RETAA,RETAB'
    output_file = run_tracer('w1inst', {'mnemonics': mnemonics}, target_binary, build_dir)
    
    try:
        # Validate format
        line_count = validate_jsonl_format(output_file)
        print(f"  ✓ Valid JSONL format ({line_count} lines)")
        
        # Parse content
        metadata, events = parse_jsonl_file(output_file)
        
        # Check metadata
        assert metadata is not None, "No metadata found"
        assert metadata['tracer'] == 'w1inst', f"Wrong tracer in metadata: {metadata.get('tracer')}"
        assert 'target_mnemonics' in metadata, "No target_mnemonics in metadata"
        assert 'modules' in metadata, "No modules in metadata"
        print(f"  ✓ Valid metadata with {len(metadata['modules'])} modules")
        
        # Check events
        assert len(events) > 0, "No events found"
        
        # Verify event structure
        event = events[0]
        assert 'data' in event, "No data in event"
        data = event['data']
        
        # Check required fields for mnemonic entry (no timestamp)
        required_fields = ['address', 'mnemonic', 'disassembly', 'instruction_count', 'module_name']
        for field in required_fields:
            assert field in data, f"Missing field '{field}' in event data"
        
        # Verify mnemonic is in target list
        target_mnemonics = mnemonics.split(',')
        assert data['mnemonic'] in target_mnemonics, f"Unexpected mnemonic: {data['mnemonic']}"
        
        print(f"  ✓ Valid events ({len(events)} instructions captured)")
        
    finally:
        os.unlink(output_file)

def test_w1mem_jsonl(build_dir, target_binary):
    """Test w1mem tracer JSONL output."""
    print("Testing w1mem JSONL output...")
    
    output_file = run_tracer('w1mem', {}, target_binary, build_dir)
    
    try:
        # Validate format
        line_count = validate_jsonl_format(output_file)
        print(f"  ✓ Valid JSONL format ({line_count} lines)")
        
        # Parse content
        metadata, events = parse_jsonl_file(output_file)
        
        # Check metadata
        assert metadata is not None, "No metadata found"
        assert metadata['tracer'] == 'w1mem', f"Wrong tracer in metadata: {metadata.get('tracer')}"
        assert 'modules' in metadata, "No modules in metadata"
        print(f"  ✓ Valid metadata with {len(metadata['modules'])} modules")
        
        # Check events
        assert len(events) > 0, "No events found"
        
        # Verify event structure
        event = events[0]
        assert 'data' in event, "No data in event"
        data = event['data']
        
        # Check required fields for memory access entry (no timestamp)
        required_fields = ['instruction_addr', 'memory_addr', 'size', 'access_type', 
                          'instruction_count', 'instruction_module', 'memory_module']
        for field in required_fields:
            assert field in data, f"Missing field '{field}' in event data"
        
        # Verify access_type is valid (1=read, 2=write)
        assert data['access_type'] in [1, 2], f"Invalid access_type: {data['access_type']}"
        
        print(f"  ✓ Valid events ({len(events)} memory accesses captured)")
        
    finally:
        os.unlink(output_file)

def main():
    """Run all JSONL integration tests."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Test JSONL output from tracers')
    parser.add_argument('--build-dir', default='build-release', 
                       help='Build directory (default: build-release)')
    parser.add_argument('--target', help='Target binary to trace')
    
    args = parser.parse_args()
    
    # Use default target if not specified
    if not args.target:
        args.target = os.path.join(args.build_dir, 'tests/programs/simple_demo')
    
    # Verify files exist
    w1tool = os.path.join(args.build_dir, 'w1tool')
    if not os.path.exists(w1tool):
        print(f"Error: w1tool not found at {w1tool}")
        sys.exit(1)
    
    if not os.path.exists(args.target):
        print(f"Error: target binary not found at {args.target}")
        sys.exit(1)
    
    print(f"Running JSONL integration tests...")
    print(f"Build directory: {args.build_dir}")
    print(f"Target binary: {args.target}")
    print()
    
    # Run tests
    try:
        test_w1xfer_jsonl(args.build_dir, args.target)
        print()
        
        test_w1inst_jsonl(args.build_dir, args.target)
        print()
        
        test_w1mem_jsonl(args.build_dir, args.target)
        print()
        
        print("All JSONL integration tests passed! ✨")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()