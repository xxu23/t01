#ifndef _MYQUEUE_H
#define _MYQUEUE_H


#ifdef __cplusplus
extern "C" {
#endif

typedef void* myqueue;

myqueue myqueue_create();

int myqueue_push(myqueue, void *item);

int myqueue_pop(myqueue, void **item);

#ifdef __cplusplus
}
#endif

#endif
