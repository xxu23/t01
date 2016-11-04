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

static int kafka_connect(struct ioengine_data *td, const char * args)
{
	struct kafka_data *kd = zmalloc(sizeof(*kd));
	char *args2 = zstrdup(args);
	char *sep, *host = (char*)args2;
	int port = 9092;
	char brokers[512];
	char tmp[16];
	char errstr[512];

	bzero(kd, sizeof(*kd));

	sep = strchr(args2, ':');
	if (sep) {
		*sep = 0;
		sep++;
		port = atoi(sep);
	}
	snprintf(brokers, sizeof(brokers), "%s:%d", host, port);

	kd->conf = rd_kafka_conf_new();/* Kafka configuration */

	/* Quick termination */
	snprintf(tmp, sizeof(tmp), "%i", SIGIO);
	rd_kafka_conf_set(kd->conf, "internal.termination.signal", tmp, NULL, 0);

	kd->topic_conf = rd_kafka_topic_conf_new();/* Topic configuration */

	/* Create Kafka handle */
	if (!(kd->rk = rd_kafka_new(RD_KAFKA_PRODUCER, kd->conf, errstr, sizeof(errstr)))) {
		t01_log(T01_WARNING, "Failed to create new producer: %s\n", errstr);
		rd_kafka_topic_conf_destroy(kd->topic_conf);
		free(kd);
		zfree(args2);
		return -1;
	}

	/* Add brokers */
	if (rd_kafka_brokers_add(kd->rk, brokers) == 0) {
		t01_log(T01_WARNING, "%% No valid brokers specified\n");
		rd_kafka_topic_conf_destroy(kd->topic_conf);
		zfree(kd);
		zfree(args2);
		return -2;
	}

	td->private = kd;
	zfree(args2);
	return 0;
}

static int kafka_disconnect(struct ioengine_data *td)
{
	struct kafka_data *kd = (struct kafka_data*)td->private;
	int run = 5;
	
	while (run-- > 0 && rd_kafka_wait_destroyed(1000) == -1)
		;

	/* Destroy conf*/
	rd_kafka_conf_destroy(kd->conf);
	/* Destroy topic */
	rd_kafka_topic_destroy(kd->rkt);

	/* Destroy the handle */
	rd_kafka_destroy(kd->rk);
	
	zfree(kd);

	return 0;
}

static int kafka_show_help()
{
	printf("--engine-opt=hostname[:port]\n"
		"hostname   : Hostname for kafka broke\n"
		"port       : Port of kafka broke\n");
	return 0;
}

static int kafka_write(struct ioengine_data *td, const char *args, int args_len,
		       const char *buffer, int len)
{
	struct kafka_data *kd = (struct kafka_data*)td->private;
	int partition = 0;

	if(!kd->rkt) {
		/* Create topic */
		kd->rkt = rd_kafka_topic_new(kd->rk, args, kd->topic_conf);
		kd->topic_conf = NULL; /* Now owned by topic */
	}


	/* Send/Produce message. */
	len = rd_kafka_produce(kd->rkt, partition, RD_KAFKA_MSG_F_COPY,
					(void*)buffer, len, NULL, 0, NULL);
	if(len == -1) {
		t01_log(T01_WARNING, "Failed to produce to topic %s partition %i: %s\n",
			rd_kafka_topic_name(kd->rkt), partition,
			rd_kafka_err2str(rd_kafka_last_error()));
		return -1;
	}
	/* Poll to handle delivery reports */
	rd_kafka_poll(kd->rk, 0);

	return len;
}

static struct ioengine_ops ioengine = {
	.name		= "kafka",
	.connect	= kafka_connect,
	.disconnect	= kafka_disconnect,
	.show_help	= kafka_show_help,
	.write	= kafka_write,
};

static void io_init io_kafka_register(void)
{
	register_ioengine(&ioengine);
}

static void io_exit io_kafka_unregister(void)
{
	unregister_ioengine(&ioengine);
}
