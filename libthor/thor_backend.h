#ifndef THOR_FRONTEND_H__
#define THOR_FRONTEND_H__

#include "thor.h"
#include "thor_internal.h"

int thor_exec_cmd_full(thor_device_handle *th,  request_type req_id,
				int req_sub_id, int *idata, int icnt,
				char **sdata, int scnt, struct res_pkt *res);

static inline int thor_exec_cmd(thor_device_handle *th,  request_type req_id,
				   int req_sub_id, int *idata, int icnt)
{
	return thor_exec_cmd_full(th, req_id, req_sub_id, idata, icnt,
				    NULL, 0, NULL);
}

int thor_send_raw_data(thor_device_handle *th,
			struct thor_data_src *data,
			off_t trans_unit_size,
			thor_progress_cb report_progress,
			void *user_data);
int thor_open(struct thor_device_id *dev_id, int wait, thor_device_handle *th);
void thor_close(thor_device_handle *th);

int thor_usb_init(thor_device_handle **handle);
void thor_usb_cleanup(thor_device_handle *th);

#endif /* THOR_FRONTEND_H__ */
