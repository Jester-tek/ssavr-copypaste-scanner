#include <stddef.h>
#include <stdint.h>
#include <ctype.h>

// Returns 1 if the character code point blocks are foreign, 0 if allowed
static inline int is_foreign_cp(uint32_t cp) {
    if (cp >= 0x0600 && cp <= 0x06FF) return 1; // Arabo
    if (cp >= 0x0400 && cp <= 0x04FF) return 1; // Cirillico
    if (cp >= 0x4E00 && cp <= 0x9FFF) return 1; // Cinese
    if (cp >= 0x3040 && cp <= 0x30FF) return 1; // Giapponese
    if (cp >= 0xAC00 && cp <= 0xD7A3) return 1; // Coreano
    if (cp >= 0x0E00 && cp <= 0x0E7F) return 1; // Tailandese
    if (cp >= 0x0590 && cp <= 0x05FF) return 1; // Ebraico
    if (cp >= 0x0900 && cp <= 0x097F) return 1; // Devanagari/Hindi
    if (cp >= 0x0B80 && cp <= 0x0CFF) return 1; // Tamil/Telugu/ecc.
    return 0;
}

// Scans UTF-8 string. Returns 1 if foreign count > threshold.
int is_foreign_content(const char *text, int threshold) {
    if (!text) return 0;
    int count = 0;
    while (*text) {
        uint32_t cp = 0;
        unsigned char c = (unsigned char)(*text);
        
        if (c < 0x80) { text++; continue; }
        else if ((c & 0xE0) == 0xC0) {
            if (!text[1]) break;
            cp = ((c & 0x1F) << 6) | ((unsigned char)text[1] & 0x3F);
            text += 2;
        }
        else if ((c & 0xF0) == 0xE0) {
            if (!text[1] || !text[2]) break;
            cp = ((c & 0x0F) << 12) | (((unsigned char)text[1] & 0x3F) << 6) | ((unsigned char)text[2] & 0x3F);
            text += 3;
        }
        else if ((c & 0xF8) == 0xF0) {
            if (!text[1] || !text[2] || !text[3]) break;
            cp = ((c & 0x07) << 18) | (((unsigned char)text[1] & 0x3F) << 12) | (((unsigned char)text[2] & 0x3F) << 6) | ((unsigned char)text[3] & 0x3F);
            text += 4;
        }
        else { text++; continue; }

        if (is_foreign_cp(cp)) {
            count++;
            if (count > threshold) return 1;
        }
    }
    return 0;
}

void index_to_string(uint64_t index, char *buf) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    const int base = 36;
    int length = 1;
    uint64_t total_before = 0;
    uint64_t block_size = base;
    while (index >= total_before + block_size) {
        total_before += block_size;
        length++;
        block_size *= base;
    }
    uint64_t remaining = index - total_before;
    buf[length] = '\0';
    for (int i = length - 1; i >= 0; i--) {
        buf[i] = charset[remaining % base];
        remaining /= base;
    }
}

// Memory-less blazing fast 64-bit hash (djb2a) that simulates python's strip() + lower().
// Extremely cache friendly and reduces Python allocations by 100%.
uint64_t fast_hash_content(const char *str) {
    if (!str) return 0;
    uint64_t hash = 5381;
    
    // Find start (strip leading whitespace)
    const char *start = str;
    while (*start == ' ' || *start == '\t' || *start == '\n' || *start == '\r') {
        start++;
    }
    
    // Find end (strip trailing whitespace)
    const char *end = start;
    const char *last = start;
    while (*end) {
        if (*end != ' ' && *end != '\t' && *end != '\n' && *end != '\r') {
            last = end;
        }
        end++;
    }
    
    if (start >= end) return 0; // Empty string

    // Compute hash for stripped range with lowercasing
    for (const char *p = start; p <= last; p++) {
        unsigned char c = (unsigned char)(*p);
        // ASCII lowercase inline
        if (c >= 'A' && c <= 'Z') c += 32;
        hash = (hash * 33) ^ c;
    }
    return hash;
}
