#include <errno.h>
#include <string.h>
#include <stdlib.h>

#ifdef __linux__
#include <linux/usb/cdc.h>
#else
#define USB_CDC_SUBCLASS_ACM			0x02

#define USB_CDC_PROTO_NONE			0
#define USB_CDC_ACM_PROTO_AT_V25TER		1
#endif

#ifdef __linux__
#include <linux/usb/ch9.h>
#else
#include <stdint.h>

#define USB_DT_INTERFACE_ASSOCIATION	0x0b

#define USB_CLASS_COMM			2
#define USB_CLASS_CDC_DATA		0x0a

struct usb_descriptor_header {
	uint8_t  bLength;
	uint8_t  bDescriptorType;
} __attribute__ ((packed));

struct usb_interface_assoc_descriptor {
	uint8_t  bLength;
	uint8_t  bDescriptorType;

	uint8_t  bFirstInterface;
	uint8_t  bInterfaceCount;
	uint8_t  bFunctionClass;
	uint8_t  bFunctionSubClass;
	uint8_t  bFunctionProtocol;
	uint8_t  iFunction;
} __attribute__ ((packed));
#endif

#include <libusb-1.0/libusb.h>

#include "thor.h"
#include "thor_internal.h"

#define MAX_SERIAL_LEN 256

struct hotplug_helper {
	struct thor_device_handle *th;
	struct thor_device_id *dev_id;
	int completed;
};

struct t_usb_transfer;

typedef void (*t_usb_transfer_cb)(struct t_usb_transfer *);

struct t_usb_transfer {
	struct libusb_transfer *ltransfer;
	t_usb_transfer_cb transfer_finished;
	off_t size;
	int ret;
	int cancelled;
};

struct t_thor_data_chunk {
	struct t_usb_transfer data_transfer;
	struct t_usb_transfer resp_transfer;
	void *user_data;
	off_t useful_size;
	struct data_res_pkt resp;
	unsigned char *buf;
	off_t trans_unit_size;
	int chunk_number;
	int data_finished;
	int resp_finished;
};

struct t_thor_data_transfer {
	struct thor_device_handle *th;
	struct thor_data_src *data;
	thor_progress_cb report_progress;
	void *user_data;
	off_t data_left;
	off_t data_sent;
	off_t data_in_progress;
	int chunk_number;
	int completed;
	int ret;
};

static struct thor_device_id *thor_choose_id(
	struct thor_device_id *user_dev_id)
{
	static struct thor_device_id default_id = {
		.busid = NULL,
		.vid = 0x04e8,
		.pid = 0x685d,
		.serial = NULL,
	};

	if (user_dev_id->busid == NULL
	    && user_dev_id->vid < 0
	    && user_dev_id->pid < 0
	    && user_dev_id->serial == NULL)
		user_dev_id = &default_id;

	return user_dev_id;
}

static int check_busid_match(const char *expected, libusb_device *dev)
{
	/* Max USB depth is 7 */
	uint8_t dev_port[8];
	int nports;
	uint8_t bus_number;
	int val;
	int i;
	int ret;

	bus_number = libusb_get_bus_number(dev);
	ret = sscanf(expected, "%d", &val);
	if (ret < 1)
		return -EINVAL;

	if (val != bus_number)
		return 0;

	expected = strchr(expected, '-');
	if (!expected)
		return -EINVAL;
	++expected;

	nports = libusb_get_port_numbers(dev, (uint8_t *)dev_port, sizeof(dev_port));
	if (nports < 0)
		return nports;


	for (i = 0; i < nports; ++i) {
		ret = sscanf(expected, "%d", &val);
		if (ret < 1)
			return -EINVAL;

		if (val != dev_port[i])
			return 0;

		expected = strchr(expected, '.');
		if (!expected) {
			if (i + 1 == nports)
				return 1;
			else
				break;
		}
		++expected;
	}

	return 0;
}

static int check_vid_pid_match(int vid, int pid, libusb_device *dev)
{
	struct libusb_device_descriptor desc;
	int ret;

	ret = libusb_get_device_descriptor(dev, &desc);
	if (ret < 0)
		return ret;

	if (vid >= 0 && vid != desc.idVendor)
		return 0;

	if (pid >= 0 && pid != desc.idProduct)
		return 0;

	return 1;
}

static int check_serial_match(const char *serial, libusb_device *dev,
		       libusb_device_handle **devh)
{
	char buf[MAX_SERIAL_LEN];
	struct libusb_device_descriptor desc;
	libusb_device_handle *handle;
	int ret;

	ret = libusb_get_device_descriptor(dev, &desc);
	if (ret < 0)
		return ret;

	ret = libusb_open(dev, &handle);
	if (ret < 0)
		return ret;

	ret = libusb_get_string_descriptor_ascii(handle, desc.iSerialNumber,
						 (unsigned char*)buf,
						 sizeof(buf));
	if (ret < 0)
		return ret;

	if (strcmp(serial, buf))
		return 0;

	*devh = handle;
	return 1;
}

static inline int
is_data_interface(const struct libusb_interface_descriptor *idesc)
{
	return idesc->bInterfaceClass == USB_CLASS_CDC_DATA;
}

static inline int
is_control_interface(const struct libusb_interface_descriptor *idesc)
{
	return idesc->bInterfaceClass == USB_CLASS_COMM
		&& idesc->bInterfaceSubClass == USB_CDC_SUBCLASS_ACM
		&& idesc->bInterfaceProtocol == USB_CDC_ACM_PROTO_AT_V25TER;
}

static int find_idesc_by_id(struct libusb_config_descriptor *cdesc, int id)
{
	int i;

	for (i = 0; i < cdesc->bNumInterfaces; ++i)
		if (cdesc->interface[i].altsetting[0].bInterfaceNumber == id)
			return i;

	return -ENODEV;
}

static int check_assoc(struct libusb_config_descriptor *cdesc,
		       struct usb_interface_assoc_descriptor *assoc_desc,
		       struct thor_device_handle *th)
{
	int intf_a, intf_b;

	if (assoc_desc->bInterfaceCount != 2
	    || assoc_desc->bFunctionClass != USB_CLASS_COMM
	    || assoc_desc->bFunctionSubClass != USB_CDC_SUBCLASS_ACM
	    || assoc_desc->bFunctionProtocol != USB_CDC_PROTO_NONE)
		return -EINVAL;

	intf_a = find_idesc_by_id(cdesc, assoc_desc->bFirstInterface);
	intf_b = find_idesc_by_id(cdesc, assoc_desc->bFirstInterface + 1);

	if (is_data_interface(cdesc->interface[intf_a].altsetting + 0)
	    && is_control_interface(cdesc->interface[intf_b].altsetting + 0)) {
		th->data_interface = intf_a;
		th->data_interface_id = assoc_desc->bFirstInterface;
		th->control_interface = intf_b;
		th->control_interface_id = assoc_desc->bFirstInterface + 1;
	} else if (is_control_interface(cdesc->interface[intf_a].altsetting + 0)
		   && is_data_interface(cdesc->interface[intf_b].altsetting + 0)) {
		th->data_interface = intf_b;
		th->data_interface_id = assoc_desc->bFirstInterface + 1;
		th->control_interface = intf_a;
		th->control_interface_id = assoc_desc->bFirstInterface;
	} else {
		return -ENODEV;
	}

	return 0;
}

static int find_interfaces(struct libusb_config_descriptor *cdesc,
			   struct thor_device_handle *th)
{
	struct usb_descriptor_header *header;
	struct usb_interface_assoc_descriptor *assoc_desc = NULL;
	int assoc_valid = 0;
	int pos;
	int ret;

	/* Try to find IAD and use it */
	pos = 0;
	for (; pos < cdesc->extra_length; pos += header->bLength) {
		header = (struct usb_descriptor_header *)(cdesc->extra + pos);
		if (header->bDescriptorType != USB_DT_INTERFACE_ASSOCIATION)
			continue;

		if (pos + sizeof(assoc_desc) > cdesc->extra_length)
			break;

		assoc_desc = (struct usb_interface_assoc_descriptor *)header;
		ret = check_assoc(cdesc, assoc_desc, th);
		if (!ret) {
			assoc_valid = 1;
			break;
		}
	}

	/*
	 * If we were unable to find IAD let's
	 * just try to manually find interfaces
	 */
	if (!assoc_valid) {
		int i;
#define get_intf_desc(_intf) (&(cdesc->interface[_intf].altsetting[0]))
		th->data_interface = -1;
		th->control_interface = -1;

		for (i = 0; i < cdesc->bNumInterfaces; ++i) {
			if (!is_data_interface(get_intf_desc(i)))
				continue;

			th->data_interface = i;
			th->data_interface_id =
				get_intf_desc(i)->bInterfaceNumber;
			break;
		}

		if (th->data_interface < 0)
			return -ENODEV;

		for (i = 0; i < cdesc->bNumInterfaces; ++i) {
			if (!is_control_interface(get_intf_desc(i)))
				continue;
			th->control_interface = i;
			th->control_interface_id =
				get_intf_desc(i)->bInterfaceNumber;
		}

		if (th->control_interface < 0)
			return -ENODEV;
#undef get_intf_desc
	}

	return 0;
}

static int find_data_eps(struct libusb_config_descriptor *cdesc,
			 struct thor_device_handle *th)
{
	const struct libusb_interface_descriptor *idesc;
	int i;

	idesc = cdesc->interface[th->data_interface_id].altsetting + 0;

	if (idesc->bNumEndpoints != 2)
		return -EINVAL;

	th->data_ep_in = -1;
	th->data_ep_out = -1;

	for (i = 0; i < idesc->bNumEndpoints; ++i) {
		if ((idesc->endpoint[i].bmAttributes & 0x03) !=
		    LIBUSB_TRANSFER_TYPE_BULK)
			return -1;
		if ((idesc->endpoint[i].bEndpointAddress & (1 << 7))
		    == LIBUSB_ENDPOINT_IN)
			th->data_ep_in = idesc->endpoint[i].bEndpointAddress;
		else
			th->data_ep_out = idesc->endpoint[i].bEndpointAddress;
	}

	if (th->data_ep_in < 0 || th->data_ep_out < 0)
		return -EINVAL;

	return 0;
}

static int find_intf_and_eps(libusb_device *dev,
			     struct thor_device_handle *th)
{
	struct libusb_config_descriptor *cdesc;
	int ret;

	ret = libusb_get_active_config_descriptor(dev, &cdesc);
	if (ret < 0)
		return ret;

	ret = find_interfaces(cdesc, th);
	if (ret) {
		ret = -ENODEV;
		goto cleanup_desc;
	}

	ret = find_data_eps(cdesc, th);
	if (ret) {
		ret = -ENODEV;
		goto cleanup_desc;
	}

	ret = 0;
cleanup_desc:
	libusb_free_config_descriptor(cdesc);
	return ret;
}

static int claim_intf(struct thor_device_handle *th)
{
	int ret;

	/*
	 * Check if our OS allows us to detach kernel driver.
	 * If yes then we mark this device as auto-detach and try to claim
	 * our interfaces. libusb will detach kernel driver, if any when we
	 * will try to claim interface.
	 * If our os doesn't support detaching kernel driver we simply try
	 * to claim our interfaces. If we fail it means that probably there
	 * is some kernel driver bound to this device but we cannot do anything
	 * with this.
	 */
	ret = libusb_has_capability(LIBUSB_CAP_SUPPORTS_DETACH_KERNEL_DRIVER);
	if (ret) {
		ret = libusb_set_auto_detach_kernel_driver(th->devh, 1);
		if (ret < 0)
			goto out;
	}

	ret = libusb_claim_interface(th->devh, th->data_interface_id);
	if (ret < 0)
		goto out;

	ret = libusb_claim_interface(th->devh, th->control_interface_id);
	if (ret < 0)
		goto release_data;

	return 0;

release_data:
	libusb_release_interface(th->devh, th->data_interface);
out:
	return ret;
}

static int check_device_match(struct thor_device_id *dev_id,
		       libusb_device *dev, struct thor_device_handle *th)
{
	int ret;

	if (dev_id->busid) {
		ret = check_busid_match(dev_id->busid, dev);
		if (ret <= 0)
			goto no_match;
	}

	if (dev_id->vid >= 0 || dev_id->pid >= 0) {
		ret = check_vid_pid_match(dev_id->vid, dev_id->pid, dev);
		if (ret <= 0)
			goto no_match;
	}

	if (dev_id->serial) {
		ret = check_serial_match(dev_id->serial, dev, &th->devh);
		if (ret <= 0)
			goto no_match;
	} else {
		ret = libusb_open(dev, &th->devh);
		if (ret < 0)
			goto no_match;
	}

	ret = find_intf_and_eps(dev, th);
	if (ret < 0)
		goto err;

	ret = claim_intf(th);
	if (ret < 0)
		goto err;

	return 1;
err:
	libusb_close(th->devh);
no_match:
	return 0;
}

static int find_existing_device(struct thor_device_id *dev_id,
			    struct thor_device_handle *th)
{
	libusb_device **dev_list;
	int i, ndevices;
	int ret = 0;

	ndevices = libusb_get_device_list(NULL, &dev_list);
	if (ndevices < 0)
		return ndevices;

	for (i = 0; i < ndevices; ++i) {
		ret = check_device_match(dev_id, dev_list[i], th);
		if (ret > 0)
			/* device match and opened */
			break;
	}

	libusb_free_device_list(dev_list, 1);

	return ret > 0 ? 1 : 0;

}

static int hotplug_device_arrived(libusb_context *ctx, libusb_device *device,
		   libusb_hotplug_event event, void *user_data)
{
	struct hotplug_helper *helper = user_data;

	if (check_device_match(helper->dev_id, device, helper->th) > 0) {
		helper->completed = 1;
		return 1;
	}

	return 0;
}

static int t_usb_find_device(struct thor_device_id *dev_id, int wait,
			     thor_device_handle *th)
{
	struct hotplug_helper helper = {
		.th = th,
		.dev_id = dev_id,
		.completed = 0,
	};
	int found;

	found = find_existing_device(dev_id, th);
	if (found <= 0) {
		if (!wait)
			return found;

		libusb_hotplug_register_callback(NULL,
						 LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED,
						 0,
						 dev_id->vid >= 0 ? dev_id->vid
						 : LIBUSB_HOTPLUG_MATCH_ANY,
						 dev_id->pid >= 0 ? dev_id->pid
						 : LIBUSB_HOTPLUG_MATCH_ANY,
						 LIBUSB_HOTPLUG_MATCH_ANY,
						 hotplug_device_arrived,
						 &helper,
						 NULL);

		while (!helper.completed)
			libusb_handle_events_completed(NULL, &helper.completed);
	}

	return 1;
}

static void t_usb_transfer_finished(struct libusb_transfer *ltransfer)
{
	struct t_usb_transfer *t = ltransfer->user_data;

	t->cancelled = 0;
	t->ret = 0;
	switch (ltransfer->status) {
	case LIBUSB_TRANSFER_COMPLETED:
		if (ltransfer->actual_length != t->size)
			t->ret = -EIO;
		break;
	case LIBUSB_TRANSFER_CANCELLED:
		t->cancelled = 1;
		break;
	default:
		t->ret = -EIO;
	}

	if (t->transfer_finished)
		t->transfer_finished(t);
}

static int t_usb_init_transfer(struct t_usb_transfer *t,
			libusb_device_handle *devh,
			unsigned char ep,
			unsigned char *buf, off_t size,
			t_usb_transfer_cb transfer_finished,
			unsigned int timeout)
{
	t->ltransfer = libusb_alloc_transfer(0);
	if (!t->ltransfer)
		return -ENOMEM;

	t->transfer_finished = transfer_finished;
	t->size = size;
	libusb_fill_bulk_transfer(t->ltransfer, devh, ep,
				  buf, size, t_usb_transfer_finished, t,
				  0);

	return 0;
}

static int t_usb_handle_events_completed(int *completed)
{
	struct timeval tv = {0, 0};
	int ret = 0;

	while (!*completed) {
		ret = libusb_handle_events_timeout_completed(NULL,
							     &tv,
							     completed);
		if (ret < 0 && ret != LIBUSB_ERROR_BUSY
		    && ret != LIBUSB_ERROR_TIMEOUT
		    && ret != LIBUSB_ERROR_OVERFLOW
		    && ret != LIBUSB_ERROR_INTERRUPTED)
			break;
		else
			ret = 0;
	}

	return ret;
}

static inline void t_usb_cleanup_transfer(struct t_usb_transfer *t)
{
	libusb_free_transfer(t->ltransfer);
}

static inline int t_usb_init_in_transfer(struct t_usb_transfer *t,
			   struct thor_device_handle *th,
			   unsigned char *buf, off_t size,
			   t_usb_transfer_cb transfer_finished,
			   unsigned int timeout)
{
	return t_usb_init_transfer(t, th->devh, th->data_ep_in, buf, size,
				   transfer_finished, timeout);
}

static inline int t_usb_init_out_transfer(struct t_usb_transfer *t,
			   struct thor_device_handle *th,
			   unsigned char *buf, off_t size,
			   t_usb_transfer_cb transfer_finished,
			   unsigned int timeout)
{
	return t_usb_init_transfer(t, th->devh, th->data_ep_out, buf, size,
				   transfer_finished, timeout);
}

static inline int t_usb_submit_transfer(struct t_usb_transfer *t)
{
	return libusb_submit_transfer(t->ltransfer);
}

static inline int t_usb_cancel_transfer(struct t_usb_transfer *t)
{
	return libusb_cancel_transfer(t->ltransfer);
}

static int t_thor_submit_chunk(struct t_thor_data_chunk *chunk)
{
	int ret;

	chunk->data_finished = chunk->resp_finished = 0;

	ret = t_usb_submit_transfer(&chunk->data_transfer);
	if (ret)
		goto out;

	memset(&chunk->resp, 0, DATA_RES_PKT_SIZE);
	ret = t_usb_submit_transfer(&chunk->resp_transfer);
	if (ret)
		goto cancel_data_transfer;

	return 0;
cancel_data_transfer:
	t_usb_cancel_transfer(&chunk->data_transfer);
out:
	return ret;
}

static int t_thor_prep_next_chunk(struct t_thor_data_chunk *chunk,
				  struct t_thor_data_transfer *transfer_data)
{
	off_t to_read;
	int ret;

	to_read = transfer_data->data_left - transfer_data->data_in_progress;
	if (to_read <= 0) {
		printf("to big data in progress\n");
		fflush(stdout);
		return -EINVAL;
	}

	chunk->useful_size = to_read > chunk->trans_unit_size ?
		chunk->trans_unit_size : to_read;

	ret = transfer_data->data->get_block(transfer_data->data,
					  chunk->buf, chunk->useful_size);
	if (ret < 0 || ret != chunk->useful_size)
		return ret;

	memset(chunk->buf + chunk->useful_size, 0,
	       chunk->trans_unit_size - chunk->useful_size);
	chunk->chunk_number = transfer_data->chunk_number++;

	ret = t_thor_submit_chunk(chunk);
	if (!ret)
		transfer_data->data_in_progress += chunk->useful_size;

	return ret;
}

static void check_next_chunk(struct t_thor_data_chunk *chunk,
			     struct t_thor_data_transfer *transfer_data)
{
	/* If there is some more data to be queued */
	if (transfer_data->data_left - transfer_data->data_in_progress) {
		int ret;

		ret = t_thor_prep_next_chunk(chunk, transfer_data);
		if (ret) {
			transfer_data->ret = ret;
			transfer_data->completed = 1;
		}
	} else {
		/* Last one turns the light off */
		if (transfer_data->data_in_progress == 0)
			transfer_data->completed = 1;
	}
}

static void data_transfer_finished(struct t_usb_transfer *_data_transfer)
{
	struct t_thor_data_chunk *chunk = container_of(_data_transfer,
						       struct t_thor_data_chunk,
						       data_transfer);
	struct t_thor_data_transfer *transfer_data = chunk->user_data;

	chunk->data_finished = 1;

	if (_data_transfer->cancelled || transfer_data->ret)
		return;

	if (_data_transfer->ret) {
		transfer_data->ret = _data_transfer->ret;
		transfer_data->completed = 1;
	}

	if (chunk->resp_finished)
		check_next_chunk(chunk, transfer_data);
}

static void resp_transfer_finished(struct t_usb_transfer *_resp_transfer)
{
	struct t_thor_data_chunk *chunk = container_of(_resp_transfer,
						       struct t_thor_data_chunk,
						       resp_transfer);
	struct t_thor_data_transfer *transfer_data = chunk->user_data;

	chunk->resp_finished = 1;
	transfer_data->data_in_progress -= chunk->useful_size;

	if (_resp_transfer->cancelled || transfer_data->ret) {
		if (transfer_data->data_in_progress == 0)
			transfer_data->completed = 1;
		return;
	}

	if (_resp_transfer->ret) {
		transfer_data->ret = _resp_transfer->ret;
		goto complete_all;
	}

	if (chunk->resp.cnt != chunk->chunk_number) {
		printf("chunk number mismatch: %d != %d\n",
			chunk->resp.cnt, chunk->chunk_number);
		fflush(stdout);
		transfer_data->ret = -EINVAL;
		goto complete_all;
	}

	transfer_data->data_sent += chunk->useful_size;
	transfer_data->data_left -= chunk->useful_size;
	if (transfer_data->report_progress)
		transfer_data->report_progress(transfer_data->th,
					       transfer_data->data,
					       transfer_data->data_sent,
					       transfer_data->data_left,
					       chunk->chunk_number,
					       transfer_data->user_data);

	if (chunk->data_finished)
		check_next_chunk(chunk, transfer_data);

	return;
complete_all:
	transfer_data->completed = 1;
}

static int t_thor_init_chunk(struct t_thor_data_chunk *chunk,
			     thor_device_handle *th,
			     off_t trans_unit_size,
			     void *user_data)
{
	int ret;

	chunk->user_data = user_data;
	chunk->useful_size = 0;
	chunk->trans_unit_size = trans_unit_size;

	chunk->buf = malloc(trans_unit_size);
	if (!chunk->buf)
		return -ENOMEM;

	ret = t_usb_init_out_transfer(&chunk->data_transfer, th, chunk->buf,
				     trans_unit_size, data_transfer_finished,
				     DEFAULT_TIMEOUT);
	if (ret)
		goto free_buf;

	ret = t_usb_init_in_transfer(&chunk->resp_transfer, th,
				     (unsigned char *)&chunk->resp,
				      DATA_RES_PKT_SIZE,
				      resp_transfer_finished,
				      2*DEFAULT_TIMEOUT);
	if (ret)
		goto cleanup_data_transfer;

	return 0;
cleanup_data_transfer:
	t_usb_cleanup_transfer(&chunk->data_transfer);
free_buf:
	free(chunk->buf);

	return ret;
}

static void t_thor_cleanup_chunk(struct t_thor_data_chunk *chunk)
{
	t_usb_cleanup_transfer(&chunk->data_transfer);
	t_usb_cleanup_transfer(&chunk->resp_transfer);
	free(chunk->buf);
}

static inline int
t_thor_handle_events(struct t_thor_data_transfer *transfer_data)
{
	return t_usb_handle_events_completed(&transfer_data->completed);
}

static inline void t_thor_cancel_chunk(struct t_thor_data_chunk *chunk)
{
	t_usb_cancel_transfer(&chunk->data_transfer);
	t_usb_cancel_transfer(&chunk->resp_transfer);
}

static int thor_usb_send_raw_data_async(thor_device_handle *th,
					struct thor_data_src *data,
					off_t trans_unit_size,
					thor_progress_cb report_progress,
					void *user_data)
{
	struct t_thor_data_chunk chunk[3];
	struct t_thor_data_transfer transfer_data;
	int i, j;
	int ret;

	for (i = 0; i < ARRAY_SIZE(chunk); ++i) {
		ret = t_thor_init_chunk(chunk + i, th, trans_unit_size,
					&transfer_data);
		if (ret)
			goto cleanup_chunks;
	}

	transfer_data.data = data;
	transfer_data.report_progress = report_progress;
	transfer_data.user_data = user_data;
	transfer_data.data_left = data->get_file_length(data);
	transfer_data.data_sent = 0;
	transfer_data.chunk_number = 1;
	transfer_data.completed = 0;
	transfer_data.data_in_progress = 0;
	transfer_data.ret = 0;

	for (i = 0;
	     i < ARRAY_SIZE(chunk)
	      && (transfer_data.data_left - transfer_data.data_in_progress > 0);
	     ++i) {
		ret = t_thor_prep_next_chunk(chunk + i, &transfer_data);
		if (ret)
			goto cancel_chunks;
	}

	t_thor_handle_events(&transfer_data);

	if (transfer_data.data_in_progress) {
		ret = transfer_data.ret;
		goto cancel_chunks;
	}

	for (i = 0; i < ARRAY_SIZE(chunk); ++i)
		t_thor_cleanup_chunk(chunk + i);

	return transfer_data.ret;

cancel_chunks:
	for (j = 0; j < i; ++j)
		t_thor_cancel_chunk(chunk + j);
	if (i) {
		transfer_data.completed = 0;
		t_thor_handle_events(&transfer_data);
	}

	i = ARRAY_SIZE(chunk);
cleanup_chunks:
	for (j = 0; j < i; ++j)
		t_thor_cleanup_chunk(chunk + j);

	return ret;
}

static int thor_usb_open(struct thor_device_id *user_dev_id,
		     int wait, thor_device_handle *th)
{
	struct thor_device_id *dev_id = thor_choose_id(user_dev_id);
	int found, ret;

	found = t_usb_find_device(dev_id, wait, th);
	if (found <= 0) {
		ret = -ENODEV;
		goto close_dev;
	}

	ret = t_acm_prepare_device(th);
	if (ret)
		goto close_dev;

	return 0;
close_dev:
	th->ops->close(th);
	return ret;
}

static void thor_usb_close(thor_device_handle *th)
{
	if (th->devh)
		libusb_close(th->devh);
}

static int thor_usb_send(struct thor_device_handle *th, unsigned char *buf,
	       off_t count, int timeout)
{
	int ret;
	int transferred = 0;

	ret = libusb_bulk_transfer(th->devh,
				   th->data_ep_out,
				   (unsigned char *)buf,
				   count,
				   &transferred,
				   timeout);

	if (ret < 0)
		return ret;
	if (transferred < count)
		return -EIO;

	return 0;
}

static int thor_usb_recv(struct thor_device_handle *th, unsigned char *buf,
	       off_t count, int timeout)
{
	int ret;
	int transferred = 0;

	ret = libusb_bulk_transfer(th->devh,
				   th->data_ep_in,
				   (unsigned char *)buf,
				   count,
				   &transferred,
				   timeout);

	if (ret < 0)
		return ret;
	if (transferred < count)
		return -EIO;

	return 0;
}

static struct thor_backend_ops thor_usb_ops = {
	.open = thor_usb_open,
	.close = thor_usb_close,
	.send = thor_usb_send,
	.recv = thor_usb_recv,
	.send_data = thor_usb_send_raw_data_async,
};

int thor_usb_init(thor_device_handle **handle)
{
	thor_device_handle *th;

	if (libusb_init(NULL) < 0)
		return -EINVAL;

	th = calloc(1, sizeof(*th));
	if (!th)
		return -ENOMEM;

	th->ops = &thor_usb_ops;

	*handle = th;

	return 0;
}

void thor_usb_cleanup(thor_device_handle *th)
{
	free(th);
	libusb_exit(NULL);
}
