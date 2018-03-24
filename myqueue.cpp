#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "myqueue.h"

#if defined(USE_CXX_BOUNDEDQUEUE)

#include <iostream>
#include "spsc-bounded-queue.hpp"

typedef spsc_bounded_queue_t<void*> queue;

myqueue myqueue_create() {
    queue *q = new queue(1<<17);
    return q;
}

int myqueue_push(myqueue q, void *item) {
    queue *q2 = (queue*)q;
    return q2->enqueue(item) ? 0 : -1;
}

int myqueue_pop(myqueue q, void **item) {
    queue *q2 = (queue*)q;
    return q2->dequeue(*item) ? 0 : -1;
}

#elif defined(USE_CXXQUEUE)

#include "concurrentqueue.h"

typedef moodycamel::ConcurrentQueue<void*> queue;

myqueue myqueue_create() {
    queue *q = new queue;
    return q;
}

int myqueue_push(myqueue q, void *item) {
    queue *q2 = (queue*)q;
    return q2->try_enqueue(item) ? 0 : -1;
}

int myqueue_pop(myqueue q, void **item) {
    queue *q2 = (queue*)q;
    return q2->try_dequeue(*item) ? 0 : -1;
}

#else

#include <libhl/queue.h>

myqueue myqueue_create() {
    return queue_create();
}

int myqueue_push(myqueue q, void *item) {
    return queue_push_right((queue_t*)q, item);
}

int myqueue_pop(myqueue q, void **item) {
    return queue_pop_left((queue_t*)q, item);
}


#endif