#define _DEFAULT_SOURCE

#include "test.h"

#include <unistd.h>

#include "mem_internals.h"
#include "mem.h"
#include "util.h"


void debug(const char *fmt, ...);

static void* test_heap_init();
static void create_new_heap(struct block_header *last_block);
static struct block_header* get_block_from_contents(void * data);


static const size_t INITIAL_HEAP_SIZE = 10000;


void test1(struct block_header *first_block) {

    void *data = _malloc(1000);

    debug_heap(stdout, first_block);

    if (first_block->is_free != false || first_block->capacity.bytes != 1000) {
        printf("Wrong capacity on test 1\n");
        return;
    }

    _free(data);
    printf("Test 1 accepted.\n\n");

}

void test2(struct block_header *first_block) {


    void *data1 = _malloc(1000);
    void *data2 = _malloc(1000);

    _free(data1);

    debug_heap(stdout, first_block);

    struct block_header *data1_block = get_block_from_contents(data1);
    struct block_header *data2_block = get_block_from_contents(data2);
    if (data1_block->is_free == false || data2_block->is_free == true) {
        printf("Wrong is_free on test 2\n");
        return;
    }

    printf("Test 2 accepted.\n\n");

    _free(data1);
    _free(data2);

}

void test3(struct block_header *first_block) {

    void *data1 = _malloc(10000);
    void *data2 = _malloc(10000);
    void *data3 = _malloc(10000);

    _free(data2);
    _free(data3);

    debug_heap(stdout, first_block);

    struct block_header *data1_block = get_block_from_contents(data1);
    struct block_header *data2_block = get_block_from_contents(data2);
    if ((uint8_t *)data1_block->contents + data1_block->capacity.bytes != (uint8_t*) data2_block){
        printf("Wrong next on test 3\n");
        return;
    }
    printf("Test 3 accepted.\n\n");

    _free(data1);
    _free(data2);
    _free(data3);

}

void test4(struct block_header *first_block) {


    void *data1 = _malloc(10000);

    struct block_header *addr = first_block;
    while (addr->next != NULL) addr = addr->next;
    create_new_heap(addr);
    void *data2 = _malloc(10000);

    debug_heap(stdout, first_block);

    struct block_header *data2_block = get_block_from_contents(data2);
    if (data2_block == addr) {
        printf("Wrong _created on test 4\n");
        return;
    }

    printf("Test 4 accepted.\n\n");

    _free(data1);
    _free(data2);
}


void test() {

    struct block_header *block = (struct block_header*) test_heap_init();

    test1(block);
    test2(block);
    test3(block);
    test4(block);

    printf("All tests has been accepted.\n");

}


static void* test_heap_init() {
    debug("Initializing heap...\n");
    void *heap = heap_init(INITIAL_HEAP_SIZE);
    if (heap == NULL) {
        err("Cannot init heap for tests.");
    }
    debug("Heap inited successfully.\n\n");
    return heap;
}

static void create_new_heap(struct block_header *last_block) {
    struct block_header *addr = last_block;
    void* test_addr = (uint8_t*) addr + size_from_capacity(addr->capacity).bytes;
    test_addr = mmap( (uint8_t*) (getpagesize() * ((size_t) test_addr / getpagesize() +
                                                   (((size_t) test_addr % getpagesize()) > 0))), 1000,
                      PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,0, 0);
    debug(test_addr);
}

static struct block_header* get_block_from_contents(void* data) {
    return (struct block_header *) ((uint8_t *) data - offsetof(struct block_header, contents));
}
