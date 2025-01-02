#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "../utilsx1.h"
#include "../thash.h"
#include "../api.h"
#include "../fors.h"
#include "../wotsx1.h"
#include "../params.h"
#include "../randombytes.h"

#define NROUNDS 13

#define log(fmt, ...) \
	        do { if (DEBUG) fprintf(stderr, "%s:%d:%s(): " fmt "\n", __FILE__, \
				                                __LINE__, __func__, __VA_ARGS__); } while (0)

#define log_info log
#define log_perr(desc) log("%s: %s", (desc), strerror(errno))
#define log_err log

#define DEBUG 1



typedef struct {
	unsigned char *data;  // Pointer to the signature data
	size_t length;        // Length of the signature
} Signature;

size_t read_signatures(const char *filename, Signature **signatures);

void free_signatures(Signature *signatures, size_t sig_count);

size_t read_signatures(const char *filename, Signature **signatures) {
	FILE *f = fopen(filename, "r");
	if (!f) {
		perror("fopen");
		*signatures = NULL;
		return 0;
	}

	char *line = NULL;
	size_t line_capacity = 0;
	size_t sig_count = 0;

	Signature *buf;

	while (getline(&line, &line_capacity, f) != -1) {
		size_t line_len = strlen(line);

		// Remove trailing newline
		if (line[line_len - 1] == '\n') {
			line[--line_len] = '\0';
		}
		log_info("line_len: %zu", line_len);

		size_t sig_len = line_len / 2; // Hex-encoded signature length is twice the binary length
		buf = realloc(*signatures, (sig_count+1) * sizeof(Signature));
		if (buf == NULL) {
			log_perr("realloc");
			*signatures = NULL;
			break;
		}
		*signatures = buf;

		// Allocate space for the decoded signature
		unsigned char *sig_data = malloc(sig_len);
		if (!sig_data) {
			log_perr("malloc");
			*signatures = NULL;
			break;
		}

		// Decode the hex-encoded signature
		for (size_t i = 0; i < sig_len; ++i) {
			int ret = sscanf(&line[i * 2], "%2hhx", &sig_data[i]);
			if (ret != 1) {
				log_err("sscanf failed: %d, %zu", ret, i);
				log_perr("sscanf");
				free(*signatures);
				*signatures = NULL;
				return 0;
			}
		}

		(*signatures)[sig_count].data = sig_data;
		(*signatures)[sig_count].length = sig_len;
		sig_count++;
	}

	free(line); // Free buffer used by getline
	fclose(f);

	return sig_count;
}

void free_signatures(Signature *signatures, size_t sig_count) {
	for (size_t i = 0; i < sig_count; ++i) {
		free(signatures[i].data);
	}
	free(signatures);
}

int main(int argc, char *argv[])
{
	if (argc != 3) {
		printf("usage: %s keyfile sigfile\n", argv[0]);
		return -1;
	}
	const char *key_file = argv[1];
	const char *sig_file = argv[2];

	/* Make stdout buffer more responsive. */
	setbuf(stdout, NULL);

	unsigned char pk[SPX_PK_BYTES];
	unsigned char sk[SPX_SK_BYTES];

	//printf("Parameters: n = %d, h = %d, d = %d, b = %d, k = %d, w = %d\n",
	//       SPX_N, SPX_FULL_HEIGHT, SPX_D, SPX_FORS_HEIGHT, SPX_FORS_TREES,
	//       SPX_WOTS_W);

	//printf("Generating keypair...\n");
	int ret = crypto_sign_keypair(pk, sk);
	if (ret) {
		log_err("crypto_sign_keypair: %d", ret);
		return 1;
	}


	// dump keys to file
	FILE *f = fopen(key_file, "w");
	if (f == NULL) {
		log_perr("fopen");
		return 1;
	}
	fprintf(f, "pk: ");
	for (int i = 0; i < SPX_PK_BYTES; ++i) {
		fprintf(f, "%02x", pk[i]);
	}
	fprintf(f, "\n");
	fprintf(f, "sk: ");
	for (int i = 0; i < SPX_SK_BYTES; ++i) {
		fprintf(f, "%02x", sk[i]);
	}
	fprintf(f, "\n");
	fclose(f);

	// clear signatures file
	fclose(fopen(sig_file, "w"));
	while (1) {
		// enter message
		char *msg = "hello world";
		size_t mlen = strlen(msg);
		// sign many times
		long long unsigned int smlen = SPX_BYTES + mlen;
		unsigned char *sm = malloc(smlen * sizeof(unsigned char));  // keep sm on the heap, since we specifically hammer the stack
		if (sm == NULL) {
			log_perr("malloc");
			return 1;
		}
		FILE *f = fopen(sig_file, "a+");
		if (f == NULL) {
			log_perr("fopen");
			return 1;
		}
		for (int i = 0; i < NROUNDS; ++i) {
			log_info("%d: %s %ld", i, msg, mlen);
			//do_flip = i==2;
			int ret = crypto_sign(sm, &smlen, (const unsigned char*)msg, mlen, sk);
			if (ret != 0) {
				log_err("crypto_sign: %d", ret);
				return 1;
			}
			for (long long unsigned int j = 0; j < smlen; ++j) {
				fprintf(f, "%02x", sm[j]);
			}
			fprintf(f, "\n");
		}
		free(sm);
		fclose(f);

		printf("press enter to start check\n");
		fflush(stdout);
		while (getchar() != '\n');
		// load signatures from file
		Signature *signatures = NULL;
		size_t sig_count = read_signatures(sig_file, &signatures);
		if (signatures == NULL) {
			log_err("read_signatures: %zu", sig_count);
			return 1;
		}
		// fake fault
		//signatures[0].data[2452] = 0;
		log_info("Read %zu signatures", sig_count);
		// open signature
		unsigned char *mout = malloc(signatures[0].length + 1);
		memset(mout, '\0', signatures[0].length);
		int flipped = 0;
		for (size_t i = 0; i < sig_count; ++i) {
			log_info("Processing signature %zu", i);
			log_info("len: %zu, SPX_BYTES: %d", signatures[i].length, SPX_BYTES);
			ret = crypto_sign_open(mout, (long long unsigned int*)&mlen, signatures[i].data, signatures[i].length, pk);
			if (ret) {
				flipped = 1;
				printf("FLIPPED: idx %zu, crypto_sign_open: %d\n", i, ret);
				break;
			}
			// check in-msg vs out-msg
			if (strcmp(msg, (char*)mout)) {
				flipped = 1;
				printf("FLIPPED: strcmp: %s != %s\n", msg, mout);
				break;
			}
		}
		free(mout);
		for (size_t i = 1; i < sig_count; ++i) {
			if (signatures[i-1].length != signatures[i].length) {
				printf("FLIPPED: length mismatch: %ld: %ld, %ld: %ld\n", i-1, signatures[i-1].length, i, signatures[i].length);
				flipped = 1;
				continue;
			}
			if (memcmp(signatures[i-1].data, signatures[i].data, signatures[i].length)) {
				printf("FLIPPED: idx %ld != %ld\n", i, i-1);
				flipped = 1;
			}
		}
		if (!flipped) {
			printf("ok\n");
		}
		free_signatures(signatures, sig_count);
	}
	return 0;
}

