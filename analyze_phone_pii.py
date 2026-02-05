#!/usr/bin/env python3
"""
Script to identify Redash query logs that could have exposed phone number PII.
Analyzes all CSV files and consolidates matching logs into a single output file.
"""

import csv
import json
import re
import sys
from pathlib import Path

# Increase CSV field size limit to handle large queries
csv.field_size_limit(sys.maxsize)

# Patterns to identify phone number columns in SQL queries
PHONE_PATTERNS = [
    r'\bto_contact(?:_\w+)?\b',  # Specific column name for phone numbers (matches to_contact, to_contact_orig, etc.)
    r'\bphone\b',
    r'\bmobile\b',
    r'\bcell\b',
    r'\btel\b',
    r'\bcontact_number\b',
    r'\bphone_number\b',
    r'\bhandphone\b',
    r'\bhp_number\b',
    r'\btelephone\b',
    r'\btelephone_number\b',
    r'\bcontact_phone\b',
    r'\bcustomer_phone\b',
    r'\brecipient_phone\b',
    r'\bsender_phone\b',
    r'\bphone_no\b',
    r'\bmobile_no\b',
    r'\bphone_num\b',
    r'\bmobile_num\b',
]

# Tables that commonly contain phone numbers
# These tables typically store phone number data
PHONE_TABLES = [
    r'\to_contact?\b',
    r'\bcontacts?\b',
    r'\baddresses?\b',
    r'\brecipients?\b',
    r'\bsenders?\b',
    r'\buser_contacts?\b',
    r'\bcustomer_contacts?\b',
    r'\bcontact_info\b',
]

def find_phone_pattern_in_query(query_text):
    """
    Find phone-related patterns in the query and return the matched pattern text.
    Returns the matched pattern text (e.g., 'to_contact', 'to_contact_orig') or None.
    """
    if not query_text:
        return None
    
    # Normalize the query text (case-insensitive)
    query_lower = query_text.lower()
    
    # First check: Does the query contain a SELECT statement?
    if not re.search(r'\bselect\b', query_lower, re.IGNORECASE):
        return None
    
    # Second check: Does the query mention phone-related column names?
    # Search in the original query (case-sensitive) to preserve the exact match
    for pattern in PHONE_PATTERNS:
        match = re.search(pattern, query_text, re.IGNORECASE)
        if match:
            # Extract the actual matched text (preserves original case)
            matched_text = match.group(0)
            return matched_text
    
    # Third check: SELECT * from tables that contain phone numbers
    # This is high-risk as it selects all columns
    if re.search(r'select\s+\*', query_lower, re.IGNORECASE):
        for table_pattern in PHONE_TABLES:
            # Try to extract the actual table name
            table_match = re.search(rf'\bfrom\s+([`"]?)([^\s,`"]*{table_pattern.replace(r"\\", "")}[^\s,`"]*)\1', query_text, re.IGNORECASE)
            if table_match:
                return f"SELECT * from {table_match.group(2)}"
    
    return None

def process_csv_file(file_path):
    """
    Process a single CSV file and return rows that contain queries with phone numbers.
    Returns list of tuples: (row_dict, matched_pattern)
    """
    matching_rows = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                # Parse the additional_properties JSON
                try:
                    additional_props = json.loads(row.get('additional_properties', '{}'))
                    query_text = additional_props.get('query', '')
                    
                    # Check if query contains phone number references and get the matched pattern
                    matched_pattern = find_phone_pattern_in_query(query_text)
                    if matched_pattern:
                        matching_rows.append((row, matched_pattern))
                except (json.JSONDecodeError, KeyError) as e:
                    # Skip rows with invalid JSON or missing query
                    continue
    
    except Exception as e:
        print(f"Error processing {file_path}: {e}", file=sys.stderr)
    
    return matching_rows

def main():
    # Get all CSV files in the current directory
    base_dir = Path(__file__).parent
    csv_files = [
        base_dir / 'execute_query_05.csv',
        base_dir / 'execute_query_06.csv',
        base_dir / 'execute_query_07.csv',
        base_dir / 'query_results_05.csv',
        base_dir / 'query_results_06.csv',
        base_dir / 'query_results_07.csv',
    ]
    
    all_matching_rows = []
    fieldnames = None
    
    # Process each file
    for csv_file in csv_files:
        if not csv_file.exists():
            print(f"Warning: {csv_file} not found, skipping...", file=sys.stderr)
            continue
        
        print(f"Processing {csv_file.name}...", file=sys.stderr)
        matching_rows = process_csv_file(csv_file)
        
        if matching_rows:
            # Store fieldnames from first file
            if fieldnames is None:
                fieldnames = list(matching_rows[0][0].keys())
                # Add the new column for matched pattern
                fieldnames.append('matched_phone_pattern')
            
            # Add the matched pattern to each row
            for row, pattern in matching_rows:
                row_copy = row.copy()
                row_copy['matched_phone_pattern'] = pattern
                all_matching_rows.append(row_copy)
            
            print(f"  Found {len(matching_rows)} matching rows", file=sys.stderr)
    
    # Write consolidated output
    output_file = base_dir / 'pii_phone_number_logs.csv'
    
    if not all_matching_rows:
        print("No matching rows found. Creating empty file with headers.", file=sys.stderr)
        # Get fieldnames from first input file if we don't have them
        if not fieldnames:
            for csv_file in csv_files:
                if csv_file.exists():
                    try:
                        with open(csv_file, 'r', encoding='utf-8') as f:
                            reader = csv.DictReader(f)
                            fieldnames = list(reader.fieldnames)
                            # Add the new column for matched pattern
                            fieldnames.append('matched_phone_pattern')
                            break
                    except:
                        continue
        
        # Create empty file with headers
        with open(output_file, 'w', encoding='utf-8', newline='') as f:
            if fieldnames:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
            else:
                # Fallback: write basic headers if we can't determine them
                f.write('id,org_id,user_id,action,object_type,object_id,additional_properties,created_at,matched_phone_pattern\n')
    else:
        print(f"\nWriting {len(all_matching_rows)} matching rows to {output_file.name}...", file=sys.stderr)
        
        with open(output_file, 'w', encoding='utf-8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_matching_rows)
    
    print(f"\nDone! Output written to: {output_file}", file=sys.stderr)
    print(f"Total rows with potential phone number PII: {len(all_matching_rows)}", file=sys.stderr)

if __name__ == '__main__':
    main()
