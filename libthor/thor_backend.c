#include <assert.h>
#include <errno.h>
#include <string.h>

#include "thor.h"
#include "thor_internal.h"

static inline int t_thor_send(thor_device_handle *th, unsigned char *buf,
						off_t count, int timeout)
{
	if (th && th->ops && th->ops->send)
		return th->ops->send(th, buf, count, timeout);

	return -ENOENT;
}

static inline int t_thor_recv(thor_device_handle *th, unsigned char *buf,
						off_t count, int timeout)
{
	if (th && th->ops && th->ops->recv)
		return th->ops->recv(th, buf, count, timeout);

	return -ENOENT;
}

static int t_thor_do_handshake(thor_device_handle *th)
{
	char challenge[] = "THOR";
	char response[] = "ROHT";
	char buffer[sizeof(response)];
	int ret;

	ret = t_thor_send(th, (unsigned char *)challenge, sizeof(challenge) - 1,
			 DEFAULT_TIMEOUT);
	if (ret < 0)
		return ret;

	ret = t_thor_recv(th, (unsigned char *)buffer, sizeof(buffer) - 1,
			 DEFAULT_TIMEOUT);
	if (ret < 0)
		return ret;

	buffer[sizeof(buffer) - 1] = '\0';

	if (strcmp(buffer, response))
		return -EINVAL;

	return 0;
}

static int t_thor_send_req(thor_device_handle *th, request_type req_id,
		   int req_sub_id, int *idata, int icnt, char **sdata, int scnt)
{
	struct rqt_pkt req;
	int i;
	int ret;

	assert(icnt <= ARRAY_SIZE(req.int_data));
	assert(icnt >= 0);
	assert(scnt <= ARRAY_SIZE(req.str_data));
	assert(scnt >= 0);

	memset(&req, 0, sizeof(req));

	req.id = req_id;
	req.sub_id = req_sub_id;

	if (idata) {
		for (i = 0; i < icnt; i++)
			req.int_data[i] = idata[i];
	}

	if (sdata) {
		for (i = 0; i < scnt; i++)
			strcpy(req.str_data[i], sdata[i]);
	}

	ret = t_thor_send(th, (unsigned char *)&req, RQT_PKT_SIZE,
			  DEFAULT_TIMEOUT);

	return ret;
}

static int t_thor_recv_req(thor_device_handle *th, struct res_pkt *resp)
{
	int ret;

	ret = t_thor_recv(th, (unsigned char *)resp, sizeof(*resp),
			  DEFAULT_TIMEOUT);

	return ret;
}

int thor_exec_cmd_full(thor_device_handle *th,  request_type req_id,
				int req_sub_id, int *idata, int icnt,
				char **sdata, int scnt, struct res_pkt *res)
{
	int ret;
	struct res_pkt resp;

	if (!res)
		res = &resp;

	ret = t_thor_send_req(th, req_id, req_sub_id, idata, icnt,
			     sdata, scnt);
	if (ret < 0)
		return ret;

	ret = t_thor_recv_req(th, res);
	if (ret < 0)
		return ret;

	return res->ack;
}

int thor_send_raw_data(thor_device_handle *th, struct thor_data_src *data,
			off_t trans_unit_size, thor_progress_cb report_progress,
			void *user_data)
{
	if (th && th->ops && th->ops->send_data)
		return th->ops->send_data(th, data, trans_unit_size,
					  report_progress, user_data);

	return -EIO;
}

int thor_open(struct thor_device_id *dev_id, int wait, thor_device_handle *th)
{
	int ret;

	if (!th || !th->ops || !th->ops->open)
		return -ENOENT;

	ret = th->ops->open(dev_id, wait, th);
	if (ret)
		return ret;

	ret = t_thor_do_handshake(th);
	if (ret) {
		th->ops->close(th);
		return ret;
	}

	return 0;
}

void thor_close(thor_device_handle *th)
{
	if (th && th->ops && th->ops->close)
		th->ops->close(th);
}
