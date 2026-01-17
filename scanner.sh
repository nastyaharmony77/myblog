#!/bin/bash
# Enhanced Backdoor Scanner with Decoding
# Usage: ./scanner.sh [path] [--deep]

RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
NC='\033[0m'

SCAN_PATH="${1:-.}"
DEEP_SCAN="${2:-}"

echo -e "${YEL}[*] Scanning: $SCAN_PATH${NC}"
echo -e "${YEL}[*] Started: $(date)${NC}"

# Diagnostic: Check if path exists and show file count
if [ ! -d "$SCAN_PATH" ] && [ ! -f "$SCAN_PATH" ]; then
    echo -e "${RED}[!] ERROR: Path does not exist: $SCAN_PATH${NC}"
    exit 1
fi

# Show quick file count for diagnostics
php_count=$(find "$SCAN_PATH" -type f -name "*.php" ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/vendor/*" ! -path "*/cache/*" 2>/dev/null | wc -l | tr -d ' ')
js_count=$(find "$SCAN_PATH" -type f -name "*.js" ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/vendor/*" ! -path "*/cache/*" 2>/dev/null | wc -l | tr -d ' ')
html_count=$(find "$SCAN_PATH" -type f \( -name "*.html" -o -name "*.htm" \) ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/vendor/*" ! -path "*/cache/*" 2>/dev/null | wc -l | tr -d ' ')

if [ "$php_count" -eq 0 ] && [ "$js_count" -eq 0 ] && [ "$html_count" -eq 0 ]; then
    echo -e "${YEL}[!] WARNING: No PHP/JS/HTML files found in: $SCAN_PATH${NC}"
    echo -e "${YEL}[*] Checking if path is correct...${NC}"
    if [ -d "$SCAN_PATH" ]; then
        echo -e "${CYN}[*] Directory exists. Listing first 5 files:${NC}"
        find "$SCAN_PATH" -maxdepth 2 -type f 2>/dev/null | head -5
    fi
    echo ""
fi

echo ""

# Exclude dirs for speed
EXCLUDE="--exclude-dir=node_modules --exclude-dir=vendor --exclude-dir=cache --exclude-dir=.git --exclude-dir=logs --exclude-dir=dist --exclude-dir=build"

# Known legitimate library markers (to reduce false positives)
LEGITIMATE_JS_MARKERS=(
    "React"
    "jQuery"
    "WordPress"
    "Gutenberg"
    "@license"
    "use-sync-external-store"
    "webpack"
    "babel"
    "MIT license"
    "Copyright"
    "This file is auto-generated"
    "underscore"
    "Vue"
    "select2"
    "knockout"
    "tinymce"
    "mediaelement"
    "plupload"
    "moxie"
    "twemoji"
    "PhotoSwipe"
    "DOMPurify"
    "imagify"
    "yaymail"
    "all-in-one-wp-migration"
    "elFinder"
    "CodeMirror"
    "coffeescript"
)

# Known library file patterns
KNOWN_LIBRARY_PATTERNS=(
    "underscore"
    "vue"
    "select2"
    "selectWoo"
    "jquery"
    "knockout"
    "tinymce"
    "mediaelement"
    "plupload"
    "moxie"
    "twemoji"
    "photoswipe"
    "dompurify"
    "purify"
    "imagify"
    "yaymail"
    "codemirror"
    "elfinder"
    "webgl"
    "three"
    "qr-code"
    "cidr"
    "jquery-payment"
    "beat"
    "coffeescript"
    "fakejshint"
    "colorpicker"
    "heartbeat"
    "wp-emoji"
    "wp-api"
    "wp-mediaelement"
    "jquery\.query"
)

# Check if file is likely minified library
is_likely_library() {
    local file="$1"
    local filename=$(basename "$file")
    
    # Check filename patterns first (faster)
    for pattern in "${KNOWN_LIBRARY_PATTERNS[@]}"; do
        if echo "$filename" | grep -qiE "$pattern"; then
            return 0  # Known library
        fi
    done
    
    local size=$(wc -c < "$file" 2>/dev/null || echo 0)
    local lines=$(wc -l < "$file" 2>/dev/null || echo 0)
    local avg_line_len=$((size / (lines + 1)))
    
    # Large files with very long lines are likely minified
    if [ "$size" -gt 100000 ] && [ "$avg_line_len" -gt 500 ]; then
        # Check for legitimate markers
        for marker in "${LEGITIMATE_JS_MARKERS[@]}"; do
            if grep -qi "$marker" "$file" 2>/dev/null; then
                return 0  # Likely legitimate library
            fi
        done
    fi
    
    # Check for common library patterns in content
    if grep -qiE "(define\.amd|module\.exports|webpack|UMD|IIFE)" "$file" 2>/dev/null; then
        if [ "$size" -gt 10000 ]; then
            return 0  # Likely library
        fi
    fi
    
    # Check for minified file patterns (common in libraries)
    if [ "$size" -gt 50000 ] && [ "$avg_line_len" -gt 200 ]; then
        # Large minified files are usually libraries
        if echo "$filename" | grep -qiE "\.min\.(js|css)"; then
            return 0  # Minified library file
        fi
    fi
    
    # Check for specific library content markers
    if grep -qiE "(jQuery|Backbone|Underscore|Vue|React|Angular|Ember|Mootools|Prototype|Dojo|YUI|ExtJS)" "$file" 2>/dev/null; then
        if [ "$size" -gt 5000 ]; then
            return 0  # Known framework/library
        fi
    fi
    
    return 1
}

# Check if file is WordPress core file (to reduce false positives)
is_wordpress_core() {
    local file="$1"
    # WordPress core paths
    if echo "$file" | grep -qiE "(wp-includes|wp-admin|wp-content/themes/twenty|wp-settings\.php|wp-config\.php)"; then
        return 0
    fi
    # Known WordPress plugin paths (common legitimate plugins)
    if echo "$file" | grep -qiE "(wp-content/plugins/(wordfence|woocommerce|yoast|advanced-custom-fields|contact-form-7|wp-mail-smtp|imagify|all-in-one-wp-migration)/)"; then
        return 0
    fi
    return 1
}

# Check if pattern is false positive for WordPress
is_wordpress_false_positive() {
    local file="$1"
    local pattern="$2"
    local context="$3"
    
    # fsockopen is normal in WordPress
    if echo "$pattern" | grep -qiE "fsockopen"; then
        if is_wordpress_core "$file"; then
            return 0  # False positive
        fi
    fi
    
    # preg_replace is normal in WordPress
    if echo "$pattern" | grep -qiE "preg_replace"; then
        if is_wordpress_core "$file"; then
            return 0  # False positive
        fi
    fi
    
    # new Function in known libraries
    if echo "$pattern" | grep -qiE "new\s+Function|new\s+function"; then
        if is_likely_library "$file" || is_wordpress_core "$file"; then
            return 0  # False positive
        fi
    fi
    
    # chr() concatenation is normal in WordPress
    if echo "$pattern" | grep -qiE "chr\s*\("; then
        if is_wordpress_core "$file"; then
            return 0  # False positive
        fi
    fi
    
    return 1
}

# Decode base64 string
decode_base64() {
    local str="$1"
    echo "$str" | base64 -d 2>/dev/null | head -c 500
}

# Decode hex string
decode_hex() {
    local str="$1"
    echo "$str" | sed 's/\\x//g' | xxd -r -p 2>/dev/null | head -c 500
}

# Decode ROT13
decode_rot13() {
    local str="$1"
    echo "$str" | tr 'A-Za-z' 'N-ZA-Mn-za-m' | head -c 500
}

# Extract and decode suspicious patterns
analyze_suspicious_code() {
    local file="$1"
    local pattern="$2"
    local output_file="$3"
    local line=$(grep -iE "$pattern" "$file" 2>/dev/null | head -1)
    
    if [ -z "$line" ]; then
        return 1
    fi
    
    # Try to extract encoded payload
    local decoded=""
    local suspicious=0
    
    # Base64 decode
    if echo "$line" | grep -qiE 'base64_decode|atob'; then
        local b64=$(echo "$line" | grep -oE '[A-Za-z0-9+/]{50,}={0,2}' | head -1)
        if [ -n "$b64" ]; then
            decoded=$(decode_base64 "$b64")
            if echo "$decoded" | grep -qiE '(eval|exec|system|shell|passthru|base64|gzinflate|assert|preg_replace.*e)'; then
                suspicious=1
            fi
        fi
    fi
    
    # Hex decode
    if echo "$line" | grep -qiE '\\x[0-9a-f]{2}'; then
        local hex=$(echo "$line" | grep -oE '\\x[0-9a-f]{2}+' | head -1)
        if [ -n "$hex" ]; then
            decoded=$(decode_hex "$hex")
            if echo "$decoded" | grep -qiE '(eval|exec|system|shell|passthru)'; then
                suspicious=1
            fi
        fi
    fi
    
    # ROT13 decode
    if echo "$line" | grep -qiE 'str_rot13'; then
        local rot13=$(echo "$line" | grep -oE '[A-Za-z]{20,}' | head -1)
        if [ -n "$rot13" ]; then
            decoded=$(decode_rot13 "$rot13")
            if echo "$decoded" | grep -qiE '(eval|exec|system|shell)'; then
                suspicious=1
            fi
        fi
    fi
    
    if [ "$suspicious" -eq 1 ] && [ -n "$decoded" ]; then
        if [ -n "$output_file" ]; then
            echo -e "${CYN}    Decoded: ${decoded:0:200}...${NC}" > "$output_file"
        else
            echo -e "${CYN}    Decoded: ${decoded:0:200}...${NC}"
        fi
        return 0
    fi
    
    return 1
}

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
    'new\s+WebSocket'
    'new\s+Function'
    'ilb\s*='
    'WebSocket\s*\('
    'ws://'
    'wss://'
)

# External domain connections to search for
EXTERNAL_DOMAINS=(
    'google-analytics\.com'
    'googlesyndication\.com'
    'googletagmanager\.com'
    'googleapis\.com'
    'gstatic\.com'
    'doubleclick\.net'
    'googleadservices\.com'
    'facebook\.net'
    'facebook\.com/tr'
    'analytics\.facebook\.com'
    'connect\.facebook\.net'
    'yandex\.ru/metrika'
    'mc\.yandex\.ru'
    'top-fwz1\.mail\.ru'
    'adfox\.ru'
    'mycdn\.ru'
    'cdn\.jsdelivr\.net'
    'cdnjs\.cloudflare\.com'
    'unpkg\.com'
    'bootstrapcdn\.com'
    'ajax\.googleapis\.com'
    'fonts\.googleapis\.com'
    'apis\.google\.com'
    'w2ed\.icu'
    # Only match real domains, not variable parts (require http/https or //)
    'https?://[a-z0-9-]+\.icu'
    '//[a-z0-9-]+\.icu'
    'https?://[a-z0-9-]+\.tk'
    '//[a-z0-9-]+\.tk'
    'https?://[a-z0-9-]+\.ml'
    '//[a-z0-9-]+\.ml'
    'https?://[a-z0-9-]+\.ga'
    '//[a-z0-9-]+\.ga'
    'https?://[a-z0-9-]+\.cf'
    '//[a-z0-9-]+\.cf'
)

# Suspicious file names to search for
SUSPICIOUS_FILENAMES=(
    'hooks\.js'
    'hook\.js'
    'init\.js'
    'loader\.js'
    'core\.js'
    'main\.js'
    'script\.js'
    'jquery\.min\.js'
    'bootstrap\.min\.js'
    'wp-admin\.js'
    'wp-includes\.js'
)

found=0

echo -e "${RED}=== PHP Backdoors ===${NC}"

# Build grep pattern
PHP_REGEX=$(IFS='|'; echo "${PHP_PATTERNS[*]}")
results=$(grep -rliE "$PHP_REGEX" $EXCLUDE --include="*.php" "$SCAN_PATH" 2>/dev/null | head -100)
if [ -n "$results" ]; then
    echo "$results" | while read f; do
        # Get matching pattern
        match_line=$(grep -iE "$PHP_REGEX" "$f" 2>/dev/null | head -1)
        if [ -z "$match_line" ]; then
            continue
        fi
        
        # Try to decode and analyze
        suspicious=false
        decoded_output=""
        tmp_file="/tmp/decoded_$$_$(basename "$f" | tr '/' '_')"
        
        for pattern in "${PHP_PATTERNS[@]}"; do
            if analyze_suspicious_code "$f" "$pattern" "$tmp_file" 2>/dev/null; then
                suspicious=true
                if [ -f "$tmp_file" ]; then
                    decoded_output=$(cat "$tmp_file")
                    rm -f "$tmp_file"
                fi
                break
            fi
        done
        
        # Check for direct suspicious patterns (without encoding)
        if echo "$match_line" | grep -qiE '(eval.*\$|assert.*\$|shell_exec.*\$|system.*\$|exec.*\$)'; then
            suspicious=true
        fi
        
        # Check for WordPress false positives
        if is_wordpress_false_positive "$f" "$match_line" "$match_line"; then
            # Skip WordPress core false positives
            continue
        fi
        
        if [ "$suspicious" = true ]; then
            echo -e "${RED}[!] SUSPICIOUS${NC} $f"
            echo -e "${YEL}    Pattern: ${match_line:0:150}${NC}"
            if [ -n "$decoded_output" ]; then
                echo "$decoded_output"
            fi
            echo ""
            found=1
        else
            # Only show if not WordPress core
            if ! is_wordpress_core "$f"; then
                echo -e "${YEL}[?] Check${NC} $f (pattern found but may be false positive)"
                echo -e "${YEL}    Pattern: ${match_line:0:100}${NC}"
                echo ""
            fi
        fi
        rm -f "$tmp_file" 2>/dev/null
    done
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
    -name "cache_.php" -o \
    -name "hooks.js" -o \
    -name "hook.js" -o \
    -name "init.js" -o \
    -name "loader.js" -o \
    -name "*hooks*.js" -o \
    -name "*hook*.js" \
\) 2>/dev/null | grep -v node_modules | grep -v vendor | head -50 | while read f; do
    # Check if it's hooks.js or similar suspicious JS
    if echo "$f" | grep -qiE '(hooks|hook|init|loader)\.js'; then
        # Skip legitimate WordPress hooks.js files
        if echo "$f" | grep -qiE '(wp-includes/js/dist/hooks\.js|wp-includes/js/hooks\.js)'; then
            continue  # Legitimate WordPress file
        fi
        
        # Skip if in known library locations
        if is_wordpress_core "$f" || is_likely_library "$f"; then
            continue
        fi
        
        echo -e "${RED}[!] SUSPICIOUS${NC} $f (suspicious JS filename)"
        # Check file content for suspicious patterns
        if grep -qiE '(eval|Function|WebSocket|atob|unescape|document\.write)' "$f" 2>/dev/null; then
            echo -e "${CYN}    Contains suspicious code patterns${NC}"
        fi
        found=1
    else
        echo -e "${YEL}[?]${NC} $f"
        found=1
    fi
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
        # Skip if likely a legitimate library
        if is_likely_library "$f"; then
            echo -e "${GRN}[~] SKIPPED (likely library)${NC} $f"
            continue
        fi
        
        # Get matching pattern
        match_line=$(grep -iE "$JS_REGEX" "$f" 2>/dev/null | head -1)
        if [ -z "$match_line" ]; then
            continue
        fi
        
        # Check if it's in a suspicious context (not in a library)
        suspicious=false
        
        # Check for eval(atob) with suspicious decoded content
        if echo "$match_line" | grep -qiE 'eval\s*\(\s*atob'; then
            # Try to extract and decode base64
            b64_match=$(echo "$match_line" | grep -oE 'atob\s*\(\s*["'"'"'][^"'"'"']{50,}["'"'"']' | sed "s/atob\s*(\s*['\"]//;s/['\"]\s*)//" | head -1)
            if [ -n "$b64_match" ]; then
                decoded=$(decode_base64 "$b64_match")
                if echo "$decoded" | grep -qiE '(eval|Function|document\.write|XMLHttpRequest|fetch|WebSocket|child_process|exec|spawn)'; then
                    suspicious=true
                fi
            fi
        fi
        
        # Check for eval(unescape)
        if echo "$match_line" | grep -qiE 'eval\s*\(\s*unescape'; then
            suspicious=true
        fi
        
        # Check for multiple String.fromCharCode (obfuscation)
        if echo "$match_line" | grep -qiE 'String\.fromCharCode.*String\.fromCharCode.*String\.fromCharCode'; then
            # Count occurrences - many means likely obfuscation
            count=$(echo "$match_line" | grep -o 'String\.fromCharCode' | wc -l)
            if [ "$count" -gt 5 ]; then
                suspicious=true
            fi
        fi
        
        # Check for new WebSocket (suspicious - can be used for C2)
        if echo "$match_line" | grep -qiE 'new\s+WebSocket|WebSocket\s*\('; then
            suspicious=true
        fi
        
        # Check for new Function (dynamic code execution)
        if echo "$match_line" | grep -qiE 'new\s+Function'; then
            # Skip if WordPress core or known library
            if ! is_wordpress_core "$f" && ! is_likely_library "$f"; then
                suspicious=true
            fi
        fi
        
        # Check for ilb= (suspicious variable pattern)
        if echo "$match_line" | grep -qiE 'ilb\s*='; then
            suspicious=true
        fi
        
        # Check for WebSocket URLs (ws:// or wss://)
        if echo "$match_line" | grep -qiE 'ws://|wss://'; then
            # Extract URL if present
            ws_url=$(echo "$match_line" | grep -oiE '(ws|wss)://[^\s"'"'"']+' | head -1)
            if [ -n "$ws_url" ]; then
                suspicious=true
            fi
        fi
        
        # Get file info (date, size)
        file_info=""
        if command -v stat >/dev/null 2>&1; then
            if stat -c "%y %s" "$f" >/dev/null 2>&1; then
                # Linux stat
                file_date=$(stat -c "%y" "$f" 2>/dev/null | cut -d'.' -f1)
                file_size=$(stat -c "%s" "$f" 2>/dev/null)
                file_info=" (${file_date}, ${file_size} bytes)"
            elif stat -f "%Sm %z" "$f" >/dev/null 2>&1; then
                # macOS stat
                file_date=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$f" 2>/dev/null)
                file_size=$(stat -f "%z" "$f" 2>/dev/null)
                file_info=" (${file_date}, ${file_size} bytes)"
            fi
        fi
        
        # Double-check if it's a known library (even if first check missed it)
        if is_likely_library "$f" || is_wordpress_core "$f"; then
            # Skip known libraries even if pattern found
            continue
        fi
        
        if [ "$suspicious" = true ]; then
            echo -e "${RED}[!] SUSPICIOUS${NC} $f${file_info}"
            echo -e "${YEL}    Pattern: ${match_line:0:150}${NC}"
            if [ -n "$decoded" ]; then
                echo -e "${CYN}    Decoded: ${decoded:0:200}...${NC}"
            fi
            if [ -n "$ws_url" ]; then
                echo -e "${CYN}    WebSocket URL: $ws_url${NC}"
            fi
            echo ""
            found=1
        else
            # Only show if not WordPress core
            if ! is_wordpress_core "$f"; then
                echo -e "${YEL}[?] Check${NC} $f${file_info} (pattern found but context unclear)"
                echo -e "${YEL}    Pattern: ${match_line:0:100}${NC}"
                echo ""
            fi
        fi
    done
fi

# WebSocket, Function, and suspicious variable patterns (all file types)
echo -e "${RED}=== WebSocket/Function/ilb Patterns (All Files) ===${NC}"
WS_PATTERNS=('new\s+WebSocket' 'new\s+Function' 'ilb\s*=')
WS_REGEX=$(IFS='|'; echo "${WS_PATTERNS[*]}")
ws_results=$(grep -rliE "$WS_REGEX" $EXCLUDE --include="*.php" --include="*.js" --include="*.html" --include="*.htm" "$SCAN_PATH" 2>/dev/null | head -100)

if [ -n "$ws_results" ]; then
    echo "$ws_results" | while read f; do
        # Skip if likely a legitimate library (for all files)
        if is_likely_library "$f"; then
            continue
        fi
        
        # Skip WordPress core files
        if is_wordpress_core "$f"; then
            continue
        fi
        
        # Get matching patterns
        match_line=$(grep -iE "$WS_REGEX" "$f" 2>/dev/null | head -1)
        if [ -z "$match_line" ]; then
            continue
        fi
        
        # Skip if it's just a comment in PHP (translators, comments, etc.)
        if [[ "$f" == *.php ]] && echo "$match_line" | grep -qiE '(translators|comment|//|/\*|new function name|introduced new function)'; then
            continue
        fi
        
        # Get all matching patterns in file
        patterns_found=$(grep -oiE "$WS_REGEX" "$f" 2>/dev/null | sort -u | tr '\n' ',' | sed 's/,$//')
        
        # Get file info (date, size, name) - like in user's example
        file_info=""
        if command -v stat >/dev/null 2>&1; then
            if stat -c "%y %s %n" "$f" >/dev/null 2>&1; then
                # Linux stat
                file_date=$(stat -c "%y" "$f" 2>/dev/null | cut -d'.' -f1)
                file_size=$(stat -c "%s" "$f" 2>/dev/null)
                file_info=" (${file_date}, ${file_size} bytes)"
            elif stat -f "%Sm %z %N" "$f" >/dev/null 2>&1; then
                # macOS stat
                file_date=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$f" 2>/dev/null)
                file_size=$(stat -f "%z" "$f" 2>/dev/null)
                file_info=" (${file_date}, ${file_size} bytes)"
            fi
        fi
        
        # Determine severity
        severity="${RED}[!]"
        reason=""
        
        # Check for WebSocket
        if echo "$match_line" | grep -qiE 'new\s+WebSocket|WebSocket\s*\('; then
            ws_url=$(echo "$match_line" | grep -oiE '(ws|wss)://[^\s"'"'"']+' | head -1)
            if [ -n "$ws_url" ]; then
                reason=" (WebSocket connection found)"
            else
                reason=" (WebSocket constructor found)"
            fi
        fi
        
        # Check for new Function
        if echo "$match_line" | grep -qiE 'new\s+Function'; then
            # Skip WordPress core, known libraries, and PHP comments
            if is_wordpress_core "$f" || is_likely_library "$f"; then
                continue
            fi
            # Skip if it's just a comment in PHP
            if [[ "$f" == *.php ]] && echo "$match_line" | grep -qiE '(translators|comment|//|/\*|introduced new function|new function name)'; then
                continue
            fi
            # Skip CodeMirror example files (index.html)
            if echo "$f" | grep -qiE "(codemirror.*index\.html|mode/.*index\.html)"; then
                continue  # Example files, not backdoors
            fi
            reason=" (dynamic Function() constructor)"
        fi
        
        # Check for ilb=
        if echo "$match_line" | grep -qiE 'ilb\s*='; then
            reason=" (suspicious variable pattern)"
        fi
        
        # Check if in suspicious location
        if echo "$f" | grep -qiE '(upload|tmp|temp|cache|wp-content/uploads)'; then
            reason="${reason} (in upload/temp directory)"
        fi
        
        echo -e "${severity}${NC} $f${file_info}${reason}"
        echo -e "${CYN}    Patterns: $patterns_found${NC}"
        echo -e "${YEL}    Context: ${match_line:0:150}${NC}"
        if [ -n "$ws_url" ]; then
            echo -e "${CYN}    WebSocket URL: $ws_url${NC}"
        fi
        echo ""
        found=1
    done
else
    echo -e "${GRN}[~] No WebSocket/Function/ilb patterns found${NC}"
fi

# Suspicious script src tags (like hooks.js from w2ed.icu)
echo -e "${RED}=== Suspicious Script Tags (script src) ===${NC}"

# First, search for w2ed.icu and hooks.js anywhere in files (broader search)
# Try multiple methods for better compatibility
hooks_results=""
# Method 1: Use grep -r (faster if it works)
if grep -rliE "(w2ed\.icu|hooks\.js|w2ed|/js/hooks)" $EXCLUDE --include="*.php" --include="*.js" --include="*.html" --include="*.htm" --include="*.txt" --include="*.tpl" --include="*.inc" "$SCAN_PATH" 2>/dev/null | head -100 > /tmp/hooks_$$ 2>/dev/null; then
    hooks_results=$(cat /tmp/hooks_$$ 2>/dev/null)
    rm -f /tmp/hooks_$$ 2>/dev/null
fi

# Method 2: Fallback to find + grep if method 1 found nothing
if [ -z "$hooks_results" ]; then
    find "$SCAN_PATH" -type f \( -name "*.php" -o -name "*.js" -o -name "*.html" -o -name "*.htm" -o -name "*.txt" -o -name "*.tpl" -o -name "*.inc" \) ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/vendor/*" ! -path "*/cache/*" ! -path "*/dist/*" ! -path "*/build/*" 2>/dev/null | while read f; do
        if grep -qiE "(w2ed\.icu|hooks\.js|w2ed|/js/hooks)" "$f" 2>/dev/null; then
            echo "$f"
        fi
    done | head -100 > /tmp/hooks_$$ 2>/dev/null
    hooks_results=$(cat /tmp/hooks_$$ 2>/dev/null)
    rm -f /tmp/hooks_$$ 2>/dev/null
fi

if [ -n "$hooks_results" ]; then
    echo "$hooks_results" | while read f; do
        # Get all matching lines
        match_lines=$(grep -iE "(w2ed\.icu|hooks\.js)" "$f" 2>/dev/null)
        
        # Check if any line contains script tag
        script_match=$(echo "$match_lines" | grep -iE "<script[^>]*src" | head -1)
        
        if [ -n "$script_match" ]; then
            # Extract script tag
            script_tag=$(echo "$script_match" | grep -oiE "<script[^>]*>.*?</script>|<script[^>]*>" | head -1)
            # Extract URL from src attribute (better pattern)
            script_url=$(echo "$script_match" | grep -oiE 'src\s*=\s*["'"'"']([^"'"'"']+)["'"'"']' | sed -E "s/.*src\s*=\s*['\"]([^'\"]+)['\"].*/\1/" | head -1)
            # Fallback if above doesn't work
            if [ -z "$script_url" ] || [ "$script_url" = "$script_match" ]; then
                script_url=$(echo "$script_match" | grep -oiE 'https?://[^"'"'"'\s<>"]+' | head -1)
            fi
            
            echo -e "${RED}[!] SUSPICIOUS${NC} $f (suspicious script src tag)"
            if [ -n "$script_url" ]; then
                echo -e "${CYN}    Script URL: $script_url${NC}"
            fi
            if [ -n "$script_tag" ]; then
                echo -e "${YEL}    Script tag: ${script_tag:0:200}${NC}"
            else
                echo -e "${YEL}    Context: ${script_match:0:200}${NC}"
            fi
            echo ""
            found=1
        else
            # If not in script tag, check if it's a false positive
            match_line=$(echo "$match_lines" | head -1)
            if [ -n "$match_line" ]; then
                # Skip if it's just "wp-hooks" or "hooks" in array/string (not a real hook)
                if echo "$match_line" | grep -qiE "('wp-hooks'|\"wp-hooks\"|array.*hooks|hooks.*array|'hooks\.js'|\"hooks\.js\"|script-loader-packages|wp-includes/assets)"; then
                    continue  # False positive - just array key or string
                fi
                # Skip if it's in a PHP array/package list (not a real script tag)
                if [[ "$f" == *.php ]] && echo "$match_line" | grep -qiE "(array\(|=>|return array|script-loader-packages|wp-includes/assets|'dependencies'.*wp-hooks)"; then
                    continue  # False positive - PHP array definition
                fi
                # Skip if file is script-loader-packages.php (known WordPress file)
                if echo "$f" | grep -qiE "script-loader-packages\.php"; then
                    continue  # Known WordPress file
                fi
                # Only report if it's actually w2ed.icu or suspicious hooks.js reference
                if echo "$match_line" | grep -qiE "(w2ed\.icu|https?://.*hooks\.js|/js/hooks)"; then
                    echo -e "${RED}[!] SUSPICIOUS${NC} $f (w2ed.icu or hooks.js reference found)"
                    echo -e "${YEL}    Context: ${match_line:0:200}${NC}"
                    echo ""
                    found=1
                fi
            fi
        fi
    done
fi

# Also search for script tags with suspicious domains
SUSPICIOUS_SCRIPT_PATTERNS=(
    'w2ed\.icu'
    'hooks\.js'
    '\.icu/js'
    '\.tk/js'
    '\.ml/js'
    '\.ga/js'
    '\.cf/js'
)
SCRIPT_REGEX=$(IFS='|'; echo "${SUSPICIOUS_SCRIPT_PATTERNS[*]}")
script_results=$(grep -rliE "(<script[^>]*src[^>]*($SCRIPT_REGEX)|src\s*=\s*['\"].*($SCRIPT_REGEX))" $EXCLUDE --include="*.php" --include="*.html" --include="*.htm" "$SCAN_PATH" 2>/dev/null | head -50)

if [ -n "$script_results" ]; then
    echo "$script_results" | while read f; do
        # Skip if already reported above
        if echo "$hooks_results" | grep -q "^$f$"; then
            continue
        fi
        
        # Get matching script tags
        script_tags=$(grep -oiE "<script[^>]*src[^>]*($SCRIPT_REGEX)[^>]*>|src\s*=\s*['\"].*($SCRIPT_REGEX)[^\"']*['\"]" "$f" 2>/dev/null | head -3)
        
        # Extract URLs
        script_urls=$(echo "$script_tags" | grep -oiE 'https?://[^"'"'"'\s>]+' | sort -u | tr '\n' ',' | sed 's/,$//')
        
        echo -e "${RED}[!] SUSPICIOUS${NC} $f (suspicious script src tag)"
        if [ -n "$script_urls" ]; then
            echo -e "${CYN}    Script URLs: $script_urls${NC}"
        fi
        echo -e "${YEL}    Tags found:${NC}"
        echo "$script_tags" | while read tag; do
            if [ -n "$tag" ]; then
                echo -e "${YEL}      ${tag:0:200}${NC}"
            fi
        done
        echo ""
        found=1
    done
fi

# Final check - if nothing found, show message
if [ -z "$hooks_results" ] && [ -z "$script_results" ]; then
    echo -e "${GRN}[~] No suspicious script tags found${NC}"
fi

# External domain connections
echo -e "${CYN}=== External Domain Connections ===${NC}"
DOMAIN_REGEX=$(IFS='|'; echo "${EXTERNAL_DOMAINS[*]}")
results=$(grep -rliE "$DOMAIN_REGEX" $EXCLUDE --include="*.php" --include="*.js" --include="*.html" --include="*.htm" "$SCAN_PATH" 2>/dev/null | head -100)

if [ -n "$results" ]; then
    echo "$results" | while read f; do
        # Skip if likely a legitimate library (for JS files)
        if [[ "$f" == *.js ]] && is_likely_library "$f"; then
            continue
        fi
        
        # Get all matching domains in this file (only real domains with protocol, not variable parts)
        # First, find lines with real URLs
        url_lines=$(grep -iE "(https?://[^\"'\\s<>]+\.(icu|tk|ml|ga|cf)|https?://[^\"'\\s<>]+(googleapis|googlesyndication|googletagmanager|google-analytics|doubleclick|facebook|yandex|cdn\.jsdelivr|cdnjs\.cloudflare))" "$f" 2>/dev/null)
        
        if [ -z "$url_lines" ]; then
            continue  # No real URLs found
        fi
        
        # Filter out false positives - skip if URL is in comment or part of longer domain
        url_lines=$(echo "$url_lines" | grep -vE '(//.*galapad|/\*.*galapad|github\.com.*\.ga|\.net.*\.ga|\.org.*\.ga|\.com.*\.ga)')
        
        if [ -z "$url_lines" ]; then
            continue  # All URLs were false positives
        fi
        
        # Extract real domains from URLs only
        domains_found=$(echo "$url_lines" | grep -oiE 'https?://([^/"]+\.(icu|tk|ml|ga|cf|com|net|org|ru))' | sed 's|https\?://||' | cut -d'/' -f1 | sort -u | tr '\n' ',' | sed 's/,$//')
        
        # Skip if no real domains found
        if [ -z "$domains_found" ]; then
            continue
        fi
        
        # Get context line (only with real URLs)
        context_line=$(echo "$url_lines" | head -1)
        
        # Determine severity based on file location and type
        severity="${YEL}[?]"
        reason=""
        
        # Check if in suspicious location
        if echo "$f" | grep -qiE '(upload|tmp|temp|cache|wp-content/uploads)'; then
            severity="${RED}[!]"
            reason=" (in upload/temp directory)"
        fi
        
        # Check if in PHP file (more suspicious than JS/HTML)
        if [[ "$f" == *.php ]]; then
            # Check if it's a direct include/require or curl
            if echo "$context_line" | grep -qiE '(include|require|curl|file_get_contents|fopen|fsockopen)'; then
                severity="${RED}[!]"
                reason=" (direct connection in PHP)"
            else
                severity="${YEL}[?]"
                reason=" (domain reference in PHP)"
            fi
        fi
        
        # Check if domain is in encoded form (suspicious)
        if echo "$context_line" | grep -qiE '(base64|atob|unescape|String\.fromCharCode|\\x[0-9a-f])'; then
            # Skip if it's a known legitimate CDN (not really obfuscated)
            if echo "$domains_found" | grep -qiE '(cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com|fonts\.googleapis\.com|ajax\.googleapis\.com|gstatic\.com)'; then
                if is_wordpress_core "$f" || is_likely_library "$f"; then
                    continue  # Known legitimate CDN, not obfuscated
                fi
            fi
            severity="${RED}[!]"
            reason=" (encoded/obfuscated domain)"
        fi
        
        # Check for highly suspicious domains (.icu, .tk, .ml, .ga, .cf) - but only if in real URL
        # Only flag if domain is in actual URL (with protocol), not variable parts or comments
        if echo "$context_line" | grep -qiE 'https?://[^/"]+\.(icu|tk|ml|ga|cf)'; then
            # Skip if it's in a comment (// or /*) or part of longer URL
            if echo "$context_line" | grep -qiE '(//.*galapad|/\*.*galapad|github\.com|\.net|\.org|\.com)'; then
                continue  # False positive - comment or part of longer URL (like galapad.net)
            fi
            # Extract the actual domain from URL
            url_domain=$(echo "$context_line" | grep -oiE 'https?://([^/"]+\.(icu|tk|ml|ga|cf))' | sed 's|https\?://||' | head -1)
            # Skip if domain is part of a longer domain (like www.ga in galapad.net)
            if echo "$context_line" | grep -qiE '(galapad|github|\.net|\.org|\.com)'; then
                continue  # Part of longer domain
            fi
            if [ -n "$url_domain" ] && ! echo "$url_domain" | grep -qiE '^(media|settings|options|nonces|image|color|bitArray|Touch|controller|library|this|e|i|n|t|r|s|a|Ga|ga|gA|mL|mejs|flickr|antix|dolby|openblox|avm99963|stefano|www\.ga|galapad)\.'; then
                severity="${RED}[!]"
                reason=" (suspicious domain: .icu/.tk/.ml/.ga/.cf TLD in URL)"
            fi
        fi
        
        # Skip known legitimate CDNs (unless highly suspicious)
        if echo "$domains_found" | grep -qiE '(cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com|fonts\.googleapis\.com|ajax\.googleapis\.com|gstatic\.com)' && [ "$severity" != "${RED}[!]" ]; then
            if is_wordpress_core "$f" || is_likely_library "$f"; then
                continue  # Known legitimate CDN in WordPress/library
            fi
        fi
        
        # Skip WordPress core false positives (unless highly suspicious like w2ed.icu)
        if is_wordpress_core "$f" && [ "$severity" != "${RED}[!]" ] && ! echo "$domains_found" | grep -qiE 'w2ed\.icu'; then
            continue
        fi
        
        # Skip known libraries (unless highly suspicious)
        if is_likely_library "$f" && [ "$severity" != "${RED}[!]" ] && ! echo "$domains_found" | grep -qiE 'w2ed\.icu'; then
            continue
        fi
        
        echo -e "${severity}${NC} $f${reason}"
        echo -e "${CYN}    Domains: $domains_found${NC}"
        echo -e "${YEL}    Context: ${context_line:0:150}${NC}"
        echo ""
        found=1
    done
else
    echo -e "${GRN}[~] No external domain connections found${NC}"
fi

# Recently modified PHP (last 7 days)
if [ "$DEEP_SCAN" = "--deep" ]; then
    echo -e "${YEL}=== Recently Modified PHP (7 days) ===${NC}"
    find "$SCAN_PATH" -type f -name "*.php" -mtime -7 2>/dev/null | \
        grep -v node_modules | grep -v vendor | grep -v cache | head -30 | while read f; do
        echo -e "${YEL}[?]${NC} $f ($(stat -c %y "$f" 2>/dev/null || stat -f %Sm "$f" 2>/dev/null))"
    done
    
    # Base64 encoded content (long strings) with decoding
    echo -e "${YEL}=== Long Base64 Strings (with decoding) ===${NC}"
    grep -rlE '[A-Za-z0-9+/]{200,}' $EXCLUDE --include="*.php" "$SCAN_PATH" 2>/dev/null | head -20 | while read f; do
        # Extract first long base64 string
        b64_str=$(grep -oE '[A-Za-z0-9+/]{200,}' "$f" 2>/dev/null | head -1)
        if [ -n "$b64_str" ]; then
            decoded=$(decode_base64 "$b64_str" 2>/dev/null)
            if [ -n "$decoded" ]; then
                # Check if decoded content is suspicious
                suspicious=false
                if echo "$decoded" | grep -qiE '(eval|exec|system|shell|passthru|base64|gzinflate|assert|preg_replace.*e|file_get_contents|file_put_contents|fwrite|fopen|curl_exec|fsockopen)'; then
                    suspicious=true
                fi
                
                # Check for external domains in decoded content
                domains_in_decoded=$(echo "$decoded" | grep -oiE "$DOMAIN_REGEX" 2>/dev/null | sort -u | tr '\n' ',' | sed 's/,$//')
                if [ -n "$domains_in_decoded" ]; then
                    suspicious=true
                    echo -e "${RED}[!] SUSPICIOUS${NC} $f (domain found in decoded base64)"
                    echo -e "${CYN}    Domains in decoded: $domains_in_decoded${NC}"
                    echo -e "${CYN}    Decoded preview: ${decoded:0:300}...${NC}"
                elif [ "$suspicious" = true ]; then
                    echo -e "${RED}[!] SUSPICIOUS${NC} $f"
                    echo -e "${CYN}    Decoded preview: ${decoded:0:300}...${NC}"
                else
                    echo -e "${YEL}[?]${NC} $f (long base64 found, decoded content seems benign)"
                fi
            else
                echo -e "${YEL}[?]${NC} $f (long base64 string found, couldn't decode)"
            fi
        fi
    done
    
    # Check for obfuscated PHP (hex, rot13, etc.)
    echo -e "${YEL}=== Obfuscated PHP Code ===${NC}"
    grep -rlE '(\\x[0-9a-f]{2}{10,}|str_rot13|chr\s*\([0-9]+\s*\)\s*\.\s*chr)' $EXCLUDE --include="*.php" "$SCAN_PATH" 2>/dev/null | head -15 | while read f; do
        match_line=$(grep -iE '(\\x[0-9a-f]{2}{10,}|str_rot13|chr\s*\([0-9]+\s*\)\s*\.\s*chr)' "$f" 2>/dev/null | head -1)
        if [ -n "$match_line" ]; then
            suspicious=false
            decoded=""
            
            # Try hex decode
            if echo "$match_line" | grep -qiE '\\x[0-9a-f]{2}'; then
                hex_str=$(echo "$match_line" | grep -oE '\\x[0-9a-f]{2}+' | head -1)
                if [ -n "$hex_str" ]; then
                    decoded=$(decode_hex "$hex_str")
                    if echo "$decoded" | grep -qiE '(eval|exec|system|shell|passthru|assert)'; then
                        suspicious=true
                    fi
                    # Check for domains in decoded hex
                    domains_in_decoded=$(echo "$decoded" | grep -oiE "$DOMAIN_REGEX" 2>/dev/null | sort -u | tr '\n' ',' | sed 's/,$//')
                    if [ -n "$domains_in_decoded" ]; then
                        suspicious=true
                    fi
                fi
            fi
            
            # Try ROT13
            if echo "$match_line" | grep -qiE 'str_rot13'; then
                rot13_str=$(echo "$match_line" | grep -oE '[A-Za-z]{30,}' | head -1)
                if [ -n "$rot13_str" ]; then
                    decoded=$(decode_rot13 "$rot13_str")
                    if echo "$decoded" | grep -qiE '(eval|exec|system|shell)'; then
                        suspicious=true
                    fi
                    # Check for domains in decoded ROT13
                    domains_in_decoded=$(echo "$decoded" | grep -oiE "$DOMAIN_REGEX" 2>/dev/null | sort -u | tr '\n' ',' | sed 's/,$//')
                    if [ -n "$domains_in_decoded" ]; then
                        suspicious=true
                    fi
                fi
            fi
            
            if [ "$suspicious" = true ]; then
                echo -e "${RED}[!] SUSPICIOUS${NC} $f"
                echo -e "${YEL}    Pattern: ${match_line:0:150}${NC}"
                if [ -n "$decoded" ]; then
                    echo -e "${CYN}    Decoded: ${decoded:0:200}...${NC}"
                    if [ -n "$domains_in_decoded" ]; then
                        echo -e "${CYN}    Domains in decoded: $domains_in_decoded${NC}"
                    fi
                fi
            else
                echo -e "${YEL}[?]${NC} $f (obfuscation found, decoded content seems benign)"
            fi
        fi
    done
fi

# Cleanup
rm -f /tmp/decoded_$$ 2>/dev/null

echo ""
echo -e "${GRN}[*] Completed: $(date)${NC}"

# Show scan statistics
echo -e "${CYN}[*] Scan Statistics:${NC}"
php_count=$(find "$SCAN_PATH" -type f -name "*.php" ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/vendor/*" ! -path "*/cache/*" 2>/dev/null | wc -l | tr -d ' ')
js_count=$(find "$SCAN_PATH" -type f -name "*.js" ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/vendor/*" ! -path "*/cache/*" 2>/dev/null | wc -l | tr -d ' ')
html_count=$(find "$SCAN_PATH" -type f \( -name "*.html" -o -name "*.htm" \) ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/vendor/*" ! -path "*/cache/*" 2>/dev/null | wc -l | tr -d ' ')
total=$((php_count + js_count + html_count))
echo -e "  Files scanned: ${total} (PHP: ${php_count}, JS: ${js_count}, HTML: ${html_count})"

if [ "$found" -eq 0 ]; then
    echo -e "${GRN}[*] No suspicious patterns found in scanned files${NC}"
    echo -e "${YEL}[*] Note: Large minified libraries are automatically skipped to reduce false positives${NC}"
else
    echo -e "${YEL}[*] Review the findings above${NC}"
fi

echo ""
echo -e "${YEL}[*] Tip: Use --deep for more thorough scan with decoding${NC}"
echo -e "${CYN}[*] Legend:${NC}"
echo -e "  ${RED}[!] SUSPICIOUS${NC} - High confidence backdoor detected"
echo -e "  ${YEL}[?] Check${NC} - Pattern found, manual review recommended"
echo -e "  ${GRN}[~] SKIPPED${NC} - Likely legitimate library, skipped"
