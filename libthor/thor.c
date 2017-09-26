/*
 * libthor - Tizen Thor communication protocol
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "thor.h"
#include "thor_internal.h"
#include "thor_backend.h"

int thor_start_session(thor_device_handle *th, off_t total)
{
	int ret;

	ret = thor_exec_cmd(th, RQT_DL, RQT_DL_INIT, (int *)&total, 1);

	return ret;
}

int thor_end_session(thor_device_handle *th)
{
	int ret;

	ret = thor_exec_cmd(th, RQT_DL, RQT_DL_EXIT, NULL, 0);

	return ret;
}

int thor_send_data(thor_device_handle *th, struct thor_data_src *data,
		   enum thor_data_type type, thor_progress_cb report_progress,
		   void *user_data, thor_next_entry_cb report_next_entry,
		   void *ne_cb_data)
{
	off_t filesize;
	const char *filename;
	struct res_pkt resp;
	int32_t int_data[2];
	off_t trans_unit_size;
	int ret;

	while (1) {
		ret = data->next_file(data);
		if (ret <= 0)
			break;
		if (report_next_entry)
			report_next_entry(th, data, ne_cb_data);

		filesize = data->get_file_length(data);
		filename = data->get_name(data);

		int_data[0] = type;
		int_data[1] = filesize;

		if (!th)
			continue;

		ret = thor_exec_cmd_full(th, RQT_DL, RQT_DL_FILE_INFO,
					   int_data, ARRAY_SIZE(int_data),
					   (char **)&filename, 1, &resp);
		if (ret < 0)
			return ret;

		trans_unit_size = resp.int_data[0];

		if (th) {
			ret = thor_exec_cmd(th, RQT_DL, RQT_DL_FILE_START,
					      NULL, 0);
			if (ret < 0)
				return ret;
		}

		ret = thor_send_raw_data(th, data, trans_unit_size,
					   report_progress, user_data);
		if (ret < 0)
			return ret;

		if (th) {
			ret = thor_exec_cmd(th, RQT_DL, RQT_DL_FILE_END,
					      NULL, 0);
			if (ret < 0)
				return ret;
		}
	}

	return 0;
}

int thor_reboot(thor_device_handle *th)
{
	int ret;

	ret = thor_exec_cmd(th, RQT_CMD, RQT_CMD_REBOOT, NULL, 0);

	return ret;
}

int thor_get_data_src(const char *path, enum thor_data_src_format format,
		      struct thor_data_src **data)
{
	int ret;

	switch (format) {
	case THOR_FORMAT_RAW:
		ret = t_file_get_data_src(path, data);
		break;
	case THOR_FORMAT_TAR:
		ret = t_tar_get_data_src(path, data);
		break;
	default:
		ret = -ENOTSUP;
	}

	return ret;
}

void thor_release_data_src(struct thor_data_src *data)
{
	if (data->release)
		data->release(data);
}
