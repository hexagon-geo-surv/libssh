#!/bin/sh

echo "Checking for missing newlines at the end of source files..."

# Find offending files using direct byte comparison (checking for hex 0a)
BAD_FILES=$(find src tests include -type f \( -name "*.c" -o -name "*.h" \) -exec sh -c '
    for f do
        # Only check non-empty files
        if [ -s "$f" ]; then
            # Extract last byte, convert to hex using od, and strip whitespaces
            last_byte=$(tail -c 1 "$f" | od -An -t x1 | tr -d " \t\n\r")

            # 0a is the hexadecimal value for a newline character (\n)
            if [ "$last_byte" != "0a" ]; then
                echo "$f"
            fi
        fi
    done
' sh {} +)

if [ -n "$BAD_FILES" ]; then
    echo "ERROR: Missing newline at end of file detected in:" >&2
    echo "$BAD_FILES" >&2
    echo "Please add a trailing newline to these files to pass this check." >&2
    exit 1
fi

echo "OK: All source files end with a newline."
exit 0
