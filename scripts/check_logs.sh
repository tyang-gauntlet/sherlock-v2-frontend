#!/bin/bash

# Configuration
EC2_HOST="ec2-52-87-176-148.compute-1.amazonaws.com"
EC2_USER="ubuntu"
KEY_PATH="../smartsmart2.pem"
REMOTE_DIR="/home/ubuntu/sherlock-v2-frontend"

# Ensure key has correct permissions
chmod 600 $KEY_PATH

# Function to show usage
show_usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -f, --follow     Follow log output (like tail -f)"
    echo "  -e, --error      Show error log instead of output log"
    echo "  -a, --analysis   Show analysis log"
    echo "  -l, --lines N    Number of lines to show (default: 50)"
    echo "  -h, --help       Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0               # Show last 50 lines of output log"
    echo "  $0 -f           # Follow output log"
    echo "  $0 -e -l 100    # Show last 100 lines of error log"
    echo "  $0 -a           # Show analysis log"
}

# Default values
FOLLOW=false
ERROR_LOG=false
ANALYSIS_LOG=false
LINES=50

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -f|--follow)
            FOLLOW=true
            shift
            ;;
        -e|--error)
            ERROR_LOG=true
            shift
            ;;
        -a|--analysis)
            ANALYSIS_LOG=true
            shift
            ;;
        -l|--lines)
            LINES="$2"
            shift
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Build the command
if [ "$ANALYSIS_LOG" = true ]; then
    LOG_FILE="/var/log/sherlock-api.analysis.log"
    echo "📊 Showing analysis log..."
elif [ "$ERROR_LOG" = true ]; then
    LOG_FILE="/var/log/sherlock-api.err.log"
    echo "❌ Showing error log..."
else
    LOG_FILE="/var/log/sherlock-api.out.log"
    echo "📝 Showing output log..."
fi

if [ "$FOLLOW" = true ]; then
    echo "🔄 Following log in real-time (Ctrl+C to exit)..."
    ssh -i $KEY_PATH $EC2_USER@$EC2_HOST "sudo tail -f $LOG_FILE"
else
    echo "📄 Showing last $LINES lines..."
    ssh -i $KEY_PATH $EC2_USER@$EC2_HOST "sudo tail -n $LINES $LOG_FILE"
fi 