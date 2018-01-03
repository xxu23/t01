/*
 * Kafka engine
 *
 */
#define _GNU_SOURCE 
#include <string.h>
#include <signal.h>
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
    int port = 9092;
    char *result = NULL;
    int i = 0;
    char *s[3] = {0};

    while((result = strtok_r(input, ":", &state)) != NULL)
    {
        if (i == 3)
            break;
        s[i++] = result;
        input = NULL;
    }
    td->host = i > 0 ? zstrdup(s[0]) : NULL;
    td->port = i > 1 ? atoi(s[1]) : port;
    td->topic = i > 2 ? zstrdup(s[2]) : "raw_queue";
    zfree(args);

    return 0;
}

static int kafka_connect(struct ioengine_data *td)
{
	struct kafka_data *kd = zmalloc(sizeof(*kd));
	char *total_param = td->total_param;
	char *host = td->host;
	int port = td->host;
	char brokers[512];
	char tmp[16];
	char errstr[512];

	bzero(kd, sizeof(*kd));

    if (strchr(total_param, ',')) {
        snprintf(brokers, sizeof(brokers), "%s", total_param);
    } else {
        snprintf(brokers, sizeof(brokers), "%s:%d", host, port);
    }

    /* Kafka configuration */
    kd->conf = rd_kafka_conf_new();

    /* Set logger */
    rd_kafka_conf_set_log_cb(kd->conf, logger);

    /* Quick termination */
    snprintf(tmp, sizeof(tmp), "%i", SIGIO);
    rd_kafka_conf_set(kd->conf, "internal.termination.signal", tmp, NULL, 0);

    /* Topic configuration */
    kd->topic_conf = rd_kafka_topic_conf_new();

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

	td->private = kd;
	return 0;
}

static int kafka_disconnect(struct ioengine_data *td)
{
	struct kafka_data *kd = (struct kafka_data*)td->private;
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
	printf("--engine-opt=hostname[:port]\n"
		"hostname   : Hostname for kafka broke\n"
		"port       : Port of kafka broke\n");
	return 0;
}

static int kafka_write(struct ioengine_data *td, const char *buffer, int len, int flush)
{
	struct kafka_data *kd = (struct kafka_data*)td->private;
	int partition = RD_KAFKA_PARTITION_UA;
	int ret;

    if(!kd->rkt) {
		/* Create topic */
		kd->rkt = rd_kafka_topic_new(kd->rk, td->topic, kd->topic_conf);
		kd->topic_conf = NULL; /* Now owned by topic */
	}

	/* Send/Produce message. */
    ret = rd_kafka_produce(kd->rkt, partition, RD_KAFKA_MSG_F_COPY,
                         buffer, len, NULL, 0, NULL);
	if(ret == -1) {
        rd_kafka_resp_err_t err = rd_kafka_last_error();
		t01_log(T01_WARNING, "Failed to produce to topic %s partition %i: %s\n",
			rd_kafka_topic_name(kd->rkt), partition,
			rd_kafka_err2str(err));
        if (err != RD_KAFKA_RESP_ERR__QUEUE_FULL)
		    return -1;
	}
	/* Poll to handle delivery reports */
    if (flush)
        rd_kafka_poll(kd->rk, 1);

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
}

static void io_exit io_kafka_unregister(void)
{
	unregister_ioengine(&ioengine);
}
