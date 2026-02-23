#!/bin/bash
# Test script to upload a CSV file and check results

FILE="/home/ictd/Desktop/Network/nal/training_pipeline/data/processed/cic_ids/flows/monday/monday__00000_20170703172558.csv"

echo "Testing file upload..."
curl -X POST -F "file=@$FILE" http://localhost:8000/api/upload | python3 -m json.tool

echo ""
echo "Checking dashboard stats after upload..."
sleep 1
curl -s http://localhost:8000/api/dashboard/stats | python3 -m json.tool | head -40
