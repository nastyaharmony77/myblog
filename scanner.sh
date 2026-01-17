#!/bin/bash
# Fast Scanner for PHP/JS
# Usage: ./backdoor_scanner.sh [path] [--deep]

RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
NC='\033[0m'

SCAN_PATH="${1:-.}"
DEEP_SCAN="${2:-}"

echo -e "${YEL}[*] Scanning: $SCAN_PATH${NC}"
echo -e "${YEL}[*] Started: $(date)${NC}"
echo ""

# Exclude dirs for speed
EXCLUDE="--exclude-dir=node_modules --exclude-dir=vendor --exclude-dir=cache --exclude-dir=.git --exclude-dir=logs"

# PHP Backdoor patterns (high confidence)
PHP_PATTERNS=(
    'eval\s*\(\s*base64_decode'
    'eval\s*\(\s*gzinflate'
    'eval\s*\(\s*gzuncompress'
    'eval\s*\(\s*str_rot13'
    'eval\s*\(\s*\$_'
    'assert\s*\(\s*\$_'
    'preg_replace\s*\(.*/[a-z]*e[a-z]*.'
    'create_function\s*\('
    '\$[a-z0-9_]*\s*\(\s*\$_'
    'base64_decode\s*\(\s*\$_'
    '\${\s*\$_'
    'chr\s*\(\s*[0-9]+\s*\)\s*\.\s*chr'
    '\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}'
    'shell_exec\s*\(\s*\$_'
    'system\s*\(\s*\$_'
    'passthru\s*\(\s*\$_'
    'exec\s*\(\s*\$_'
    'popen\s*\(\s*\$_'
    'proc_open\s*\('
    'fsockopen\s*\('
    'move_uploaded_file.*\$_FILES'
    'file_put_contents.*\$_'
    '@\s*include\s*\(\s*\$_'
    'call_user_func.*\$_'
)

# Known webshell signatures
SIGNATURES=(
    'c99shell'
    'r57shell'
    'WSO '
    'FilesMan'
    'b374k'
    'adminer'
    'webshell'
    'Locus7Shell'
    'mini shell'
    'phpspy'
    'PHPJackal'
    'Antichat'
    'Safe0ver'
    'GRP WebShell'
)

# JS patterns
JS_PATTERNS=(
    'eval\s*\(\s*atob'
    'eval\s*\(\s*unescape'
    'document\.write\s*\(\s*unescape'
    'String\.fromCharCode.*String\.fromCharCode.*String\.fromCharCode'
    'eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k'
)

found=0

echo -e "${RED}=== PHP Backdoors ===${NC}"

# Build grep pattern
PHP_REGEX=$(IFS='|'; echo "${PHP_PATTERNS[*]}")
results=$(grep -rliE "$PHP_REGEX" $EXCLUDE --include="*.php" "$SCAN_PATH" 2>/dev/null | head -100)
if [ -n "$results" ]; then
    echo "$results" | while read f; do
        echo -e "${RED}[!]${NC} $f"
        # Show matching line
        grep -iE "$PHP_REGEX" "$f" 2>/dev/null | head -1 | cut -c1-100
        echo ""
    done
    found=1
fi

# Signature scan
echo -e "${RED}=== Known Webshells ===${NC}"
SIG_REGEX=$(IFS='|'; echo "${SIGNATURES[*]}")
results=$(grep -rli "$SIG_REGEX" $EXCLUDE --include="*.php" "$SCAN_PATH" 2>/dev/null | head -50)
if [ -n "$results" ]; then
    echo "$results" | while read f; do
        echo -e "${RED}[!]${NC} $f"
    done
    found=1
fi

# Suspicious filenames
echo -e "${YEL}=== Suspicious Filenames ===${NC}"
find "$SCAN_PATH" -type f \( \
    -name "*.php.suspected" -o \
    -name "*.php.bak" -o \
    -name "*.php.old" -o \
    -name "*.php.orig" -o \
    -name "*.php.1" -o \
    -name "*.phtml" -o \
    -name "*.phar" -o \
    -name "*shell*.php" -o \
    -name "*backdoor*.php" -o \
    -name "*hack*.php" -o \
    -name "*bypass*.php" -o \
    -name "wp-tmp.php" -o \
    -name "wp-feed.php" -o \
    -name "wp-vcd.php" -o \
    -name "class-wp-*.php" -o \
    -name "*.ico.php" -o \
    -name "content.php" -o \
    -name "db_.php" -o \
    -name "cache_.php" \
\) 2>/dev/null | grep -v node_modules | grep -v vendor | head -50 | while read f; do
    echo -e "${YEL}[?]${NC} $f"
    found=1
done

# PHP in upload/image dirs
echo -e "${YEL}=== PHP in Upload/Image Dirs ===${NC}"
find "$SCAN_PATH" -type f -name "*.php" \( \
    -path "*/uploads/*" -o \
    -path "*/upload/*" -o \
    -path "*/images/*" -o \
    -path "*/image/*" -o \
    -path "*/img/*" -o \
    -path "*/tmp/*" -o \
    -path "*/temp/*" -o \
    -path "*/cache/*" \
\) 2>/dev/null | grep -v node_modules | head -30 | while read f; do
    echo -e "${YEL}[?]${NC} $f"
    found=1
done

# JS Backdoors
echo -e "${RED}=== JS Backdoors ===${NC}"
JS_REGEX=$(IFS='|'; echo "${JS_PATTERNS[*]}")
results=$(grep -rliE "$JS_REGEX" $EXCLUDE --include="*.js" "$SCAN_PATH" 2>/dev/null | head -50)
if [ -n "$results" ]; then
    echo "$results" | while read f; do
        echo -e "${RED}[!]${NC} $f"
    done
    found=1
fi

# Recently modified PHP (last 7 days)
if [ "$DEEP_SCAN" = "--deep" ]; then
    echo -e "${YEL}=== Recently Modified PHP (7 days) ===${NC}"
    find "$SCAN_PATH" -type f -name "*.php" -mtime -7 2>/dev/null | \
        grep -v node_modules | grep -v vendor | grep -v cache | head -30 | while read f; do
        echo -e "${YEL}[?]${NC} $f ($(stat -c %y "$f" 2>/dev/null || stat -f %Sm "$f" 2>/dev/null))"
    done
    
    # Base64 encoded content (long strings)
    echo -e "${YEL}=== Long Base64 Strings ===${NC}"
    grep -rlE '[A-Za-z0-9+/]{200,}' $EXCLUDE --include="*.php" "$SCAN_PATH" 2>/dev/null | head -20 | while read f; do
        echo -e "${YEL}[?]${NC} $f"
    done
fi

echo ""
echo -e "${GRN}[*] Completed: $(date)${NC}"
echo -e "${YEL}[*] Tip: Use --deep for more thorough scan${NC}"
