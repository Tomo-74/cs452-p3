#include <stdio.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <string.h>
#include <stddef.h>
#include <assert.h>
#include <signal.h>
#include <execinfo.h>
#include <unistd.h>
#include <time.h>
#ifdef __APPLE__
#include <sys/errno.h>
#else
#include <errno.h>
#endif

#include "lab.h"

#define handle_error_and_die(msg) \
    do                            \
    {                             \
        perror(msg);              \
        raise(SIGKILL);          \
    } while (0)

size_t btok(size_t bytes)
{
    // Edge case
    if(!bytes) return 0;

    size_t k = 0; // Guarantee enough space for the header

    // Count the number of bits needed to represent bytes
    while(bytes > 0)
    {
        bytes >>= 1; // Divide by 2
        k++;
    }

    return k;
}

struct avail *buddy_calc(struct buddy_pool *pool, struct avail *block)
{
    uintptr_t addr = (uintptr_t)block - (uintptr_t)pool->base;  // Get relative address of block
    uintptr_t mask = UINT64_C(1) << block->kval;                // Mask for calculating buddy address
    return (struct avail *) (pool->base + (addr ^ mask));       // XOR to get buddy address
}

void *buddy_malloc(struct buddy_pool *pool, size_t size)
{
    // Input validation
    if(!pool || size > pool->numbytes || size <= 0)
    {
        errno = ENOMEM;
        return NULL;
    }

    // Retrieve the kval for the requested size with enough room for the header
    size_t k = btok(size + HEADER_SIZE);
    if(k < SMALLEST_K) k = SMALLEST_K;

    //R1 Find a block
    size_t j = k;
    while(j <= pool->kval_m) 
    {
        if(pool->avail[j].next != &pool->avail[j])
            break;
        j++;
    }

    //There was not enough memory to satisfy the request thus we need to set error and return NULL
    if(j > pool->kval_m) 
    {
        errno = ENOMEM;
        return NULL;
    }

    //R2 Remove from list;
    struct avail *L = pool->avail[j].next;
    struct avail *P = L->next;
    pool->avail[j].next = P;
    P->prev = &pool->avail[j];
    L->tag = BLOCK_RESERVED;

    //R3 and R4 Split the block if required
    while(j > k)
    {
        j--;
        P = (struct avail *) ((size_t)L + (UINT64_C(1) << j));   // L + 2**j
        P->tag = BLOCK_AVAIL;
        P->kval = j;
        P->next = P->prev = &pool->avail[j];
        pool->avail[j].next = pool->avail[j].prev = P;
    }
    L->kval = j;

    return (void *) ((char *)L + HEADER_SIZE); // Skip the header when passing the block back to the user
}

void buddy_free(struct buddy_pool *pool, void *ptr)
{
    // Do nothing if void pointer
    if(!pool || !ptr) return;

    struct avail *L = (struct avail *)(ptr - HEADER_SIZE); // Retrieve header
    struct avail *P; // Buddy of L
    
    size_t k = L->kval;
    size_t m = pool->kval_m;

    while(true)
    {
        // S1 Is buddy available?
        P = buddy_calc(pool, L);

        if( (k == m || P->tag == BLOCK_RESERVED) || (P->tag == BLOCK_AVAIL && P->kval != k) )
            break;

        // S2 Combine with buddy
        P->prev->next = P->next;
        P->next->prev = P->prev;
        P->kval++;
        if(P < L) L = P;
    }

    // S3 Put block L on the avail list
    L->tag = BLOCK_AVAIL;
    P = pool->avail[k].next;
    L->next = P;
    P->prev = L;
    L->kval = k;
    L->prev = &pool->avail[k];
    pool->avail[k].next = L;
}

void buddy_init(struct buddy_pool *pool, size_t size)
{
    size_t kval = 0;
    if (size == 0)
        kval = DEFAULT_K;
    else
        kval = btok(size);

    if (kval < MIN_K)
        kval = MIN_K;
    if (kval > MAX_K)
        kval = MAX_K - 1;

    //make sure pool struct is cleared out
    memset(pool,0,sizeof(struct buddy_pool));
    pool->kval_m = kval;
    pool->numbytes = (UINT64_C(1) << pool->kval_m);
    //Memory map a block of raw memory to manage
    pool->base = mmap(
        NULL,                               /*addr to map to*/
        pool->numbytes,                     /*length*/
        PROT_READ | PROT_WRITE,             /*prot*/
        MAP_PRIVATE | MAP_ANONYMOUS,       /*flags*/
        -1,                                 /*fd -1 when using MAP_ANONYMOUS*/
        0                                   /* offset 0 when using MAP_ANONYMOUS*/
    );
    if (MAP_FAILED == pool->base)
    {
        handle_error_and_die("buddy_init avail array mmap failed");
    }

    //Set all blocks to empty. We are using circular lists so the first elements just point
    //to an available block. Thus the tag, and kval feild are unused burning a small bit of
    //memory but making the code more readable. We mark these blocks as UNUSED to aid in debugging.
    for (size_t i = 0; i <= kval; i++)
    {
        pool->avail[i].next = pool->avail[i].prev = &pool->avail[i];
        pool->avail[i].kval = i;
        pool->avail[i].tag = BLOCK_UNUSED;
    }

    //Add in the first block
    pool->avail[kval].next = pool->avail[kval].prev = (struct avail *)pool->base;
    struct avail *m = pool->avail[kval].next;
    m->tag = BLOCK_AVAIL;
    m->kval = kval;
    m->next = m->prev = &pool->avail[kval];
}

void buddy_destroy(struct buddy_pool *pool)
{
    int rval = munmap(pool->base, pool->numbytes);
    if (-1 == rval)
    {
        handle_error_and_die("buddy_destroy avail array");
    }
    //Zero out the array so it can be reused it needed
    memset(pool,0,sizeof(struct buddy_pool));
}

#define UNUSED(x) (void)x

// /**
//  * This function can be useful to visualize the bits in a block. This can
//  * help when figuring out the buddy_calc function!
//  */
// static void printb(unsigned long int b)
// {
//      size_t bits = sizeof(b) * 8;
//      unsigned long int curr = UINT64_C(1) << (bits - 1);
//      for (size_t i = 0; i < bits; i++)
//      {
//           if (b & curr)
//           {
//                printf("1");
//           }
//           else
//           {
//                printf("0");
//           }
//           curr >>= 1L;
//      }
// }
