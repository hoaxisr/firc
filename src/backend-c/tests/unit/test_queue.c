#include "greatest.h"

#include <pthread.h>

#include "firc/queue.h"

TEST reject_policy_drops_and_counts(void)
{
    firc_queue_t *q = firc_queue_create(2, FIRC_QUEUE_REJECT);
    ASSERT(q != NULL);

    int a = 1, b = 2, c = 3;
    ASSERT_EQ(FIRC_OK, firc_queue_push(q, &a, NULL));
    ASSERT_EQ(FIRC_OK, firc_queue_push(q, &b, NULL));
    ASSERT_EQ(FIRC_ERR_LIMIT, firc_queue_push(q, &c, NULL));
    ASSERT_EQ(1u, (unsigned)firc_queue_dropped(q));
    ASSERT_EQ(2u, (unsigned)firc_queue_len(q));

    void *item = NULL;
    ASSERT_EQ(FIRC_OK, firc_queue_try_pop(q, &item));
    ASSERT_EQ(&a, item);
    ASSERT_EQ(FIRC_OK, firc_queue_try_pop(q, &item));
    ASSERT_EQ(&b, item);
    ASSERT_EQ(FIRC_ERR_AGAIN, firc_queue_try_pop(q, &item));

    firc_queue_destroy(q);
    PASS();
}

TEST drop_oldest_policy_evicts_head(void)
{
    firc_queue_t *q = firc_queue_create(2, FIRC_QUEUE_DROP_OLDEST);
    ASSERT(q != NULL);

    int a = 1, b = 2, c = 3;
    ASSERT_EQ(FIRC_OK, firc_queue_push(q, &a, NULL));
    ASSERT_EQ(FIRC_OK, firc_queue_push(q, &b, NULL));

    void *evicted = NULL;
    ASSERT_EQ(FIRC_OK, firc_queue_push(q, &c, &evicted));
    ASSERT_EQ(&a, evicted);
    ASSERT_EQ(1u, (unsigned)firc_queue_dropped(q));

    void *item = NULL;
    ASSERT_EQ(FIRC_OK, firc_queue_try_pop(q, &item));
    ASSERT_EQ(&b, item);
    ASSERT_EQ(FIRC_OK, firc_queue_try_pop(q, &item));
    ASSERT_EQ(&c, item);

    firc_queue_destroy(q);
    PASS();
}

TEST pop_timeout_expires(void)
{
    firc_queue_t *q = firc_queue_create(1, FIRC_QUEUE_REJECT);
    ASSERT(q != NULL);
    void *item = NULL;
    ASSERT_EQ(FIRC_ERR_TIMEOUT, firc_queue_pop(q, &item, 20));
    firc_queue_destroy(q);
    PASS();
}

TEST close_wakes_and_drains(void)
{
    firc_queue_t *q = firc_queue_create(4, FIRC_QUEUE_REJECT);
    ASSERT(q != NULL);
    int a = 1;
    ASSERT_EQ(FIRC_OK, firc_queue_push(q, &a, NULL));
    firc_queue_close(q);

    ASSERT_EQ(FIRC_ERR_CLOSED, firc_queue_push(q, &a, NULL));

    void *item = NULL;
    ASSERT_EQ(FIRC_OK, firc_queue_pop(q, &item, -1));
    ASSERT_EQ(&a, item);
    ASSERT_EQ(FIRC_ERR_CLOSED, firc_queue_pop(q, &item, -1));

    firc_queue_destroy(q);
    PASS();
}

#define PRODUCER_ITEMS 1000

static void *producer_thread(void *arg)
{
    firc_queue_t *q = arg;
    static int values[PRODUCER_ITEMS];
    for (int i = 0; i < PRODUCER_ITEMS; i++) {
        values[i] = i;
        while (firc_queue_push(q, &values[i], NULL) == FIRC_ERR_LIMIT) {
            sched_yield();
        }
    }
    return NULL;
}

TEST concurrent_producer_consumer(void)
{
    firc_queue_t *q = firc_queue_create(16, FIRC_QUEUE_REJECT);
    ASSERT(q != NULL);

    pthread_t th;
    ASSERT_EQ(0, pthread_create(&th, NULL, producer_thread, q));

    int received = 0;
    while (received < PRODUCER_ITEMS) {
        void *item = NULL;
        firc_err_t err = firc_queue_pop(q, &item, 1000);
        ASSERT_EQ(FIRC_OK, err);
        ASSERT_EQ(received, *(int *)item);
        received++;
    }
    pthread_join(th, NULL);
    firc_queue_destroy(q);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(reject_policy_drops_and_counts);
    RUN_TEST(drop_oldest_policy_evicts_head);
    RUN_TEST(pop_timeout_expires);
    RUN_TEST(close_wakes_and_drains);
    RUN_TEST(concurrent_producer_consumer);
    GREATEST_MAIN_END();
}
