#include <memory.h>
#include <mm_malloc.h>

#include "sha3/sph_blake.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"
#include "sha3/sph_bmw.h"


#include "lyra2/Lyra2.h"

#include "miner.h"

void lyra2rev2_hash(uint64_t* wholeMatrix, void *state, const void *input, uint32_t height)
{
	struct timespec spec;
    clock_gettime(CLOCK_REALTIME, &spec);
    double start = spec.tv_sec + spec.tv_nsec / 1.0e9;

	uint32_t _ALIGN(64) hash[16];

	LYRA2(wholeMatrix, hash, 32, input, 80, input, 80, 2, height, 256);

    if (hash[0] % 32 == 0) {
    	clock_gettime(CLOCK_REALTIME, &spec);
    	double end = spec.tv_sec + spec.tv_nsec / 1.0e9;
    	printf("Hash time: %f ms\n", (end - start) * 1000);
    }

	memcpy(state, hash, 32);
}

int scanhash_lyra2rev2(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done, uint32_t height)
{

	size_t size = (int64_t) ((int64_t) height * 256 * 96);
    uint64_t *wholeMatrix = _mm_malloc(size, 64);

	uint32_t _ALIGN(128) hash[8];
	uint32_t _ALIGN(128) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;

	if (opt_benchmark)
		ptarget[7] = 0x0000ff;

	for (int i=0; i < 19; i++) {
		be32enc(&endiandata[i], pdata[i]);
	}

	do {
		be32enc(&endiandata[19], nonce);
		lyra2rev2_hash(wholeMatrix, hash, endiandata, height);

		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			work_set_target_ratio(work, hash);
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
			_mm_free(wholeMatrix);
			return 1;
		}
		nonce++;

	} while (nonce < max_nonce && !work_restart[thr_id].restart);

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	_mm_free(wholeMatrix);
	return 0;
}
