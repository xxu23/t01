/*
 * Kafka engine
 *
 */
#define _GNU_SOURCE 
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include "../ioengine.h"
#include "../zmalloc.h"
#include "rdkafka.h"
#include "logger.h"

struct kafka_data {
	rd_kafka_topic_t *rkt;
	rd_kafka_t *rk;
	rd_kafka_conf_t *conf;
	rd_kafka_topic_conf_t *topic_conf;
};

/**
 * Kafka logger callback (optional)
 */
static void logger (const rd_kafka_t *rk, int level,
                    const char *fac, const char *buf) {
    t01_log(T01_WARNING, "LIBRDKAFKA-%i-%s: %s: %s",
            level, fac, rk ? rd_kafka_name(rk) : NULL, buf);
}

static int kafka_init(struct ioengine_data *td, const char *param)
{
    char *args = zstrdup(param), *input = args;
    char *state;
    char *result = NULL;
    int i = 0;
    char *s[4] = {0};

    while((result = strtok_r(input, ";", &state)) != NULL)
    {
        if (i == 3)
            break;
        s[i++] = result;
        input = NULL;
    }
    td->host = i > 0 ? zstrdup(s[0]) : NULL;
    td->topic = i > 1 ? zstrdup(s[1]) : "raw_queue";
	td->partitions = i > 2 ? atoi(s[2]) : 1;
    zfree(args);

    return 0;
}

static int kafka_connect(struct ioengine_data *td)
{
	struct kafka_data *kd = zmalloc(sizeof(*kd));
	char *total_param = td->total_param;
	char *host = td->host;
	char brokers[512];
	char tmp[16];
	char errstr[512];

	bzero(kd, sizeof(*kd));

    snprintf(brokers, sizeof(brokers), "%s", host);

    /* Kafka configuration */
    kd->conf = rd_kafka_conf_new();

    /* Set logger */
    rd_kafka_conf_set_log_cb(kd->conf, logger);

    /* Quick termination */
    snprintf(tmp, sizeof(tmp), "%i", SIGIO);
    rd_kafka_conf_set(kd->conf, "internal.termination.signal", tmp, NULL, 0);

    /* Producer config */
    rd_kafka_conf_set(kd->conf, "queue.buffering.max.messages", "500000",
                      NULL, 0);
    rd_kafka_conf_set(kd->conf, "message.send.max.retries", "3", NULL, 0);
    rd_kafka_conf_set(kd->conf, "retry.backoff.ms", "500", NULL, 0);

    /* Topic configuration */
    kd->topic_conf = rd_kafka_topic_conf_new();

    rd_kafka_topic_conf_set(kd->topic_conf, "request.required.acks",
                                0, errstr, sizeof(errstr));

	/* Create Kafka handle */
	if (!(kd->rk = rd_kafka_new(RD_KAFKA_PRODUCER, kd->conf, errstr, sizeof(errstr)))) {
		t01_log(T01_WARNING, "Failed to create new producer: %s", errstr);
		rd_kafka_topic_conf_destroy(kd->topic_conf);
		free(kd);
		return -1;
	}

    /* Add brokers */
	if (rd_kafka_brokers_add(kd->rk, brokers) == 0) {
		t01_log(T01_WARNING, "%% No valid brokers specified");
		rd_kafka_topic_conf_destroy(kd->topic_conf);
		zfree(kd);
		return -2;
	}

	td->private_data = kd;
	return 0;
}

static int kafka_disconnect(struct ioengine_data *td)
{
	struct kafka_data *kd = (struct kafka_data*)td->private_data;
	int run = 5;

    /* Destroy topic */
    rd_kafka_topic_destroy(kd->rkt);

    /* Destroy the handle */
    rd_kafka_destroy(kd->rk);

    if (kd->topic_conf)
        rd_kafka_topic_conf_destroy(kd->topic_conf);

	while (run-- > 0 && rd_kafka_wait_destroyed(1000) == -1)
		;

    /* Destroy conf*/
	//rd_kafka_conf_destroy(kd->conf);
	
	zfree(kd);

	return 0;
}

static int kafka_ping(struct ioengine_data *td) {
	return 0;
}

static int kafka_show_help()
{
	printf("--engine-opt=hostname[;topic]\n"
		"hostlist   : Hostname for kafka broke\n"
		"topic      : kafka topic\n");
	return 0;
}

static int kafka_write(struct ioengine_data *td, const char *buffer, int len,
					   uint32_t hash_idx, int flush)
{
	struct kafka_data *kd = (struct kafka_data*)td->private_data;
	int partition = hash_idx % td->partitions;
	int ret;

    if(!kd->rkt) {
		/* Create topic */
		kd->rkt = rd_kafka_topic_new(kd->rk, td->topic, kd->topic_conf);
		kd->topic_conf = NULL; /* Now owned by topic */
	}

	/* Send/Produce message. */
    ret = rd_kafka_produce(kd->rkt, partition, 0,
                           (void*)buffer, len, NULL, 0, NULL);
	if(ret == -1) {
        rd_kafka_resp_err_t err = rd_kafka_last_error();
		if (err == RD_KAFKA_RESP_ERR__QUEUE_FULL) {
			/* If the internal queue is full, wait for
             * messages to be delivered and then retry.
             * The internal queue represents both
             * messages to be sent and messages that have
             * been sent or failed, awaiting their
             * delivery report callback to be called.
             *
             * The internal queue is limited by the
             * configuration property
             * queue.buffering.max.messages */
            rd_kafka_poll(kd->rk, 10);
            return len;
		} else {
            t01_log(T01_WARNING, "Failed to produce to topic %s partition %i: %s\n",
                    rd_kafka_topic_name(kd->rkt), partition,
                    rd_kafka_err2str(err));
            return -1;
		}
	}

	/* A producer application should continually serve
	 * the delivery report queue by calling rd_kafka_poll()
	 * at frequent intervals.
	 * */
	rd_kafka_poll(kd->rk, 0/*non-blocking*/);

	return len;
}

static struct ioengine_ops ioengine = {
	.name		= "kafka",
    .init       = kafka_init,
	.connect	= kafka_connect,
	.disconnect	= kafka_disconnect,
	.ping		= kafka_ping,
	.show_help	= kafka_show_help,
	.write	    = kafka_write,
};

static void io_init io_kafka_register(void)
{
	register_ioengine(&ioengine);
    t01_log(T01_NOTICE, "Using librdkafka version %s",
            rd_kafka_version_str());
}

static void io_exit io_kafka_unregister(void)
{
	unregister_ioengine(&ioengine);
}
