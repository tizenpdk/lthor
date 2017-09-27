#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "thor.h"
#include "thor_internal.h"

static int t_net_connect_device(struct thor_device_id *dev_id, int wait,
				thor_device_handle *th)
{
	struct sockaddr_in server;
	int s;
	int ret;

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0)
		return -EIO;

	memset(&server, 0, sizeof(server));

	ret = inet_pton(AF_INET, dev_id->ip_addr, &server.sin_addr);
	if (ret <= 0) {
		fprintf(stderr, "IP addr is not valid:%s\n", dev_id->ip_addr);
		return -EINVAL;
	}
	server.sin_family = AF_INET;
	server.sin_port = htons(dev_id->port);

reconnect:
	if (connect(s, (struct sockaddr *)&server, sizeof(server)) < 0) {
		if (!wait) {
			close(s);
			return -ENODEV;
		}
		/*FIXME:
		 * Register callbacks for check connection instead of polling
		 */
		sleep(1);
		goto reconnect;
	}

	fprintf(stderr, "success to connect server: %s\n", dev_id->ip_addr);

	th->data_ep_in = th->data_ep_out = s;

	return 0;
}

static int thor_net_open(struct thor_device_id *user_dev_id,
		     int wait, thor_device_handle *th)
{
	int ret;

	if (!user_dev_id->ip_addr || !user_dev_id->port) {
		fprintf(stderr, "net mode requires --ip-addr and --tcp-port\n");
		return -EINVAL;
	}

	ret = t_net_connect_device(user_dev_id, wait, th);
	if (ret)
		return -ENODEV;

	return 0;
}

static void thor_net_close(thor_device_handle *th)
{
	close(th->data_ep_in);
}

static int thor_net_send(thor_device_handle *th, unsigned char *buf,
	       off_t count, int timeout)
{
	int transferred = 0;

	transferred = send(th->data_ep_out, buf, count, 0);

	if (transferred < count)
		return -EIO;

	return 0;
}

static int thor_net_recv(thor_device_handle *th, unsigned char *buf,
	       off_t count, int timeout)
{
	int transferred = 0;

	transferred = recv(th->data_ep_in, buf, count, MSG_WAITALL);

	if (transferred < count)
		return -EIO;

	return 0;
}

static int t_thor_net_send_chunk(thor_device_handle *th, unsigned char *chunk,
				 off_t size, int chunk_number)
{
	struct data_res_pkt resp;
	int ret;

	ret = thor_net_send(th, chunk, size, 0);
	if (ret < 0)
		return ret;

	memset(&resp, 0, DATA_RES_PKT_SIZE);

	ret = thor_net_recv(th, (unsigned char *)&resp, DATA_RES_PKT_SIZE, 0);
	if (ret < 0)
		return ret;

	if (resp.cnt != chunk_number)
		return ret;

	return resp.ack;
}

static int thor_net_send_raw_data(thor_device_handle *th,
				  struct thor_data_src *data,
				  off_t trans_unit_size,
				  thor_progress_cb report_progress,
				  void *user_data)
{
	unsigned char *chunk;
	off_t data_left;
	off_t size;
	off_t data_sent = 0;
	int chunk_number = 1;
	int ret;

	chunk = malloc(trans_unit_size);
	if (!chunk)
		return -ENOMEM;

	data_left = data->get_file_length(data);

	while (data_left) {
		size = data_left > trans_unit_size ?
			trans_unit_size : data_left;

		ret = data->get_block(data, chunk, size);
		if (ret < 0 || ret != size)
			goto cleanup;

		memset(chunk + size, 0, trans_unit_size - size);
		if (th) {
			ret = t_thor_net_send_chunk(th, chunk, trans_unit_size,
							chunk_number);
			if (ret)
				goto cleanup;
		}

		data_sent += size;
		data_left -= size;
		++chunk_number;
		if (report_progress)
			report_progress(NULL, data, data_sent, data_left,
					chunk_number, user_data);
	}

	ret = 0;

cleanup:
	free(chunk);
	return ret;
}


static struct thor_backend_ops thor_net_ops = {
	.open = thor_net_open,
	.close = thor_net_close,
	.send = thor_net_send,
	.recv = thor_net_recv,
	.send_data = thor_net_send_raw_data,
};

int thor_net_init(thor_device_handle **handle)
{
	thor_device_handle *th;

	th = calloc(1, sizeof(*th));
	if (!th)
		return -ENOMEM;

	th->ops = &thor_net_ops;

	*handle = th;

	return 0;
}

void thor_net_cleanup(thor_device_handle *th)
{
	free(th);
}
