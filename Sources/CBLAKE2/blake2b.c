#if __aarch64__
#include "../../neon/blake2b.c"
#elif defined(__SSE2__) || defined(__x86_64__) || defined(__amd64__)
#include "../../sse/blake2b.c"
#endif
