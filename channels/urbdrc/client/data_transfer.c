/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * RemoteFX USB Redirection
 *
 * Copyright 2012 Atrust corp.
 * Copyright 2012 Alfred Liu <alfred.liu@atruscorp.com>
 * Copyright 2017 Armin Novak <akallabeth@posteo.net>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <winpr/sysinfo.h>

#include "urbdrc_types.h"
#include "data_transfer.h"
#include "urbdrc_main.h"

static wStream* stream_create_base(size_t size, UINT32 InterfaceId, UINT32 MessageId,
                                   UINT32 FunctionId)
{
	wStream* out = Stream_New(NULL, size + 12);

	if (!out)
		return NULL;

	Stream_Write_UINT32(out, InterfaceId);
	Stream_Write_UINT32(out, MessageId);
	Stream_Write_UINT32(out, FunctionId);
	return out;
}


static wStream* stream_create(size_t size, UINT32 InterfaceId, UINT32 MessageId,
                              UINT32 FunctionId, UINT32 RequestId, UINT32 hResult)
{
	wStream* out = stream_create_base(size + 16, InterfaceId, MessageId, FunctionId);

	if (!out)
		return NULL;

	Stream_Write_UINT32(out, RequestId);
	Stream_Write_UINT32(out, hResult);
	Stream_Write_UINT32(out, size);
	Stream_Write_UINT32(out, size);
	return out;
}

static UINT stream_write_and_free(IUDEVICE* pdev, URBDRC_CHANNEL_CALLBACK* callback, wStream* out)
{
	UINT rc = CHANNEL_RC_OK;

	if (!pdev || !callback || !out || !pdev->isSigToEnd || !callback->channel ||
	    !callback->channel->Write)
		return CHANNEL_RC_BAD_CHANNEL;

	Stream_SealLength(out);

	if (!pdev->isSigToEnd(pdev))
		rc = callback->channel->Write(callback->channel, Stream_Length(out), Stream_Buffer(out), NULL);

	Stream_Free(out, TRUE);
	return rc;
}

static UINT32 usb_process_get_port_status(IUDEVICE* pdev)
{
	int bcdUSB = pdev->query_device_descriptor(pdev, BCD_USB);

	switch (bcdUSB)
	{
		case USB_v1_0:
			return 0x303;

		case USB_v1_1:
			return 0x103;

		case USB_v2_0:
		default:
			return 0x503;
	}
}

#if ISOCH_FIFO

static int func_check_isochronous_fds(IUDEVICE* pdev)
{
	int ret = 0;
	BYTE* data_temp;
	UINT32 size_temp, process_times = 2;
	ISOCH_CALLBACK_QUEUE* isoch_queue = NULL;
	ISOCH_CALLBACK_DATA* isoch = NULL;
	URBDRC_CHANNEL_CALLBACK* callback;
	isoch_queue = (ISOCH_CALLBACK_QUEUE*) pdev->get_isoch_queue(pdev);

	while (process_times)
	{
		process_times--;

		if (isoch_queue == NULL || !pdev)
			return -1;

		pthread_mutex_lock(&isoch_queue->isoch_loading);

		if (isoch_queue->head == NULL)
		{
			pthread_mutex_unlock(&isoch_queue->isoch_loading);
			continue;
		}
		else
		{
			isoch = isoch_queue->head;
		}

		if (!isoch || !isoch->out_data)
		{
			pthread_mutex_unlock(&isoch_queue->isoch_loading);
			continue;
		}
		else
		{
			callback = (URBDRC_CHANNEL_CALLBACK*) isoch->callback;
			size_temp = isoch->out_size;
			data_temp = isoch->out_data;
			ret = isoch_queue->unregister_data(isoch_queue, isoch);

			if (!ret)
				WLog_DBG(TAG, "isoch_queue_unregister_data: Not found isoch data!!");

			pthread_mutex_unlock(&isoch_queue->isoch_loading);

			if (pdev && !pdev->isSigToEnd(pdev))
			{
				callback->channel->Write(callback->channel, size_temp, data_temp, NULL);
				zfree(data_temp);
			}
		}
	}

	return 0;
}

#endif

static UINT urbdrc_process_register_request_callback(URBDRC_CHANNEL_CALLBACK* callback,
        wStream* in, IUDEVMAN* udevman, UINT32 UsbDevice)
{
	IUDEVICE* pdev;
	UINT32 NumRequestCompletion = 0;
	UINT32 RequestCompletion = 0;
	size_t rem;
	WLog_DBG(TAG, "urbdrc_process_udev_data_transfer:"
	         " >>REGISTER_REQUEST_CALLBACK<<");

	if (!callback || !in || !udevman)
		return CHANNEL_RC_BAD_CHANNEL;

	pdev = udevman->get_udevice_by_UsbDevice(udevman, UsbDevice);

	if (pdev == NULL)
		return CHANNEL_RC_OK;

	rem = Stream_GetRemainingLength(in);

	if (rem < 4)
		return CHANNEL_RC_NULL_DATA;
	else if (rem >= 8)
	{
		Stream_Read_UINT32(in, NumRequestCompletion); /** must be 1 */
		/** RequestCompletion:
		*   unique Request Completion interface for the client to use */
		Stream_Read_UINT32(in, RequestCompletion);
		pdev->set_ReqCompletion(pdev, RequestCompletion);
	}
	else /** Unregister the device */
	{
		Stream_Read_UINT32(in, RequestCompletion);

		if (1)//(pdev->get_ReqCompletion(pdev) == RequestCompletion)
		{
			/** The wrong driver may also receive this message, So we
			 *  need some time(default 3s) to check the driver or delete
			 *  it */
			sleep(3);
			callback->channel->Write(callback->channel, 0, NULL, NULL);
			pdev->SigToEnd(pdev);
		}
	}

	return CHANNEL_RC_OK;
}

static UINT urbdrc_process_cancel_request(wStream* in, IUDEVMAN* udevman,
        UINT32 UsbDevice)
{
	IUDEVICE* pdev;
	UINT32 CancelId;

	if (!in || !udevman)
		return CHANNEL_RC_BAD_CHANNEL;

	if (Stream_GetRemainingLength(in) < 4)
		return CHANNEL_RC_NULL_DATA;

	Stream_Read_UINT32(in, CancelId); /** RequestId */
	WLog_DBG(TAG, "urbdrc_process_udev_data_transfer:"
	         " >>CANCEL_REQUEST<< CancelId=0x%"PRIX32"", CancelId);
	pdev = udevman->get_udevice_by_UsbDevice(udevman, UsbDevice);

	if (pdev == NULL)
		return CHANNEL_RC_OK;

	return pdev->cancel_transfer_request(pdev, CancelId);
}

static UINT urbdrc_process_retract_device_request(wStream* in, IUDEVMAN* udevman,
        UINT32 UsbDevice)
{
	UINT32 Reason;
	WLog_DBG(TAG, "urbdrc_process_udev_data_transfer:"
	         " >>RETRACT_DEVICE<<");

	if (!in || !udevman)
		return CHANNEL_RC_BAD_CHANNEL;

	if (Stream_GetRemainingLength(in) < 4)
		return CHANNEL_RC_NULL_DATA;

	Stream_Read_UINT32(in, Reason); /** Reason */

	switch (Reason)
	{
		case UsbRetractReason_BlockedByPolicy:
			WLog_DBG(TAG, "UsbRetractReason_BlockedByPolicy: now it is not support");
			return CHANNEL_RC_INITIALIZATION_ERROR;

		default:
			WLog_DBG(TAG, "urbdrc_process_retract_device_request: Unknown Reason %"PRIu32"", Reason);
			return CHANNEL_RC_INITIALIZATION_ERROR;
	}
}

static UINT urbdrc_process_io_control(URBDRC_CHANNEL_CALLBACK* callback, wStream* in,
                                      UINT32 MessageId, IUDEVMAN* udevman, UINT32 UsbDevice)
{
	IUDEVICE* pdev;
	UINT32 InterfaceId;
	UINT32 IoControlCode;
	UINT32 InputBufferSize;
	UINT32 OutputBufferSize;
	UINT32 RequestId;
	UINT32 usbd_status = USBD_STATUS_SUCCESS;
	wStream* out;
	int success = 0;
	WLog_DBG(TAG, "urbdrc_process_udev_data_transfer:"
	         " >>IO_CONTROL<<");

	if (!callback || !in || !udevman)
		return CHANNEL_RC_BAD_CHANNEL;

	if (Stream_GetRemainingLength(in) < 16)
		return CHANNEL_RC_NULL_DATA;

	Stream_Read_UINT32(in, IoControlCode);
	Stream_Read_UINT32(in, InputBufferSize);

	if (Stream_GetRemainingLength(in) < InputBufferSize + 8)
		return CHANNEL_RC_NULL_DATA;

	Stream_Seek(in, InputBufferSize);
	Stream_Read_UINT32(in, OutputBufferSize);
	Stream_Read_UINT32(in, RequestId);
	pdev = udevman->get_udevice_by_UsbDevice(udevman, UsbDevice);

	if (pdev == NULL)
		return 0;

	InterfaceId = ((STREAM_ID_PROXY << 30) | pdev->get_ReqCompletion(pdev));
	out = stream_create(OutputBufferSize, InterfaceId, MessageId, IOCONTROL_COMPLETION, RequestId,
	                    USBD_STATUS_SUCCESS);

	if (!out)
		return ERROR_OUTOFMEMORY;

	/**  process */

	switch (IoControlCode)
	{
		case IOCTL_INTERNAL_USB_SUBMIT_URB:  /** 0x00220003 */
			WLog_DBG(TAG, "ioctl: IOCTL_INTERNAL_USB_SUBMIT_URB");
			WLog_ERR(TAG,  " Function IOCTL_INTERNAL_USB_SUBMIT_URB: Unchecked");
			Stream_Seek(out, OutputBufferSize);
			break;

		case IOCTL_INTERNAL_USB_RESET_PORT:  /** 0x00220007 */
			WLog_DBG(TAG, "ioctl: IOCTL_INTERNAL_USB_RESET_PORT");
			Stream_Seek(out, OutputBufferSize);
			break;

		case IOCTL_INTERNAL_USB_GET_PORT_STATUS: /** 0x00220013 */
			WLog_DBG(TAG, "ioctl: IOCTL_INTERNAL_USB_GET_PORT_STATUS");
			success = pdev->query_device_port_status(pdev, &usbd_status, &OutputBufferSize, Stream_Buffer(out));

			if (success)
			{
				UINT32 status = 0;

				if (pdev->isExist(pdev) != 0)
					status = usb_process_get_port_status(pdev);

				Stream_Write_UINT32(out, status);
				Stream_Rewind(out, 4);
				WLog_DBG(TAG, "PORT STATUS(fake!):0x%04"PRIx32, status);
			}

			Stream_Seek(out, OutputBufferSize);
			break;

		case IOCTL_INTERNAL_USB_CYCLE_PORT:  /** 0x0022001F */
			WLog_DBG(TAG, "ioctl: IOCTL_INTERNAL_USB_CYCLE_PORT");
			WLog_ERR(TAG,  " Function IOCTL_INTERNAL_USB_CYCLE_PORT: Unchecked");
			Stream_Seek(out, OutputBufferSize);
			break;

		case IOCTL_INTERNAL_USB_SUBMIT_IDLE_NOTIFICATION: /** 0x00220027 */
			WLog_DBG(TAG, "ioctl: IOCTL_INTERNAL_USB_SUBMIT_IDLE_NOTIFICATION");
			WLog_ERR(TAG,  " Function IOCTL_INTERNAL_USB_SUBMIT_IDLE_NOTIFICATION: Unchecked");
			Stream_Seek(out, OutputBufferSize);
			break;

		default:
			WLog_DBG(TAG, "urbdrc_process_io_control: unknown IoControlCode 0x%"PRIX32"", IoControlCode);
			Stream_Free(out, TRUE);
			return ERROR_INVALID_OPERATION;
	}

	return stream_write_and_free(pdev, callback, out);
}

static UINT urbdrc_process_internal_io_control(URBDRC_CHANNEL_CALLBACK* callback, wStream* in,
        UINT32 MessageId, IUDEVMAN* udevman, UINT32 UsbDevice)
{
	IUDEVICE* pdev;
	wStream* out;
	UINT32 IoControlCode, InterfaceId, InputBufferSize;
	UINT32 OutputBufferSize, RequestId, frames;
	WLog_DBG(TAG, "urbdrc_process_udev_data_transfer:"
	         " >>INTERNAL_IO_CONTROL<<");

	if (!callback || !in || !udevman)
		return CHANNEL_RC_BAD_CHANNEL;

	if (Stream_GetRemainingLength(in) < 16)
		return CHANNEL_RC_NULL_DATA;

	Stream_Read_UINT32(in, IoControlCode);
	Stream_Read_UINT32(in, InputBufferSize);
	Stream_Read_UINT32(in, OutputBufferSize);
	Stream_Read_UINT32(in, RequestId);
	pdev = udevman->get_udevice_by_UsbDevice(udevman, UsbDevice);

	if (pdev == NULL)
		return 0;

	InterfaceId = ((STREAM_ID_PROXY << 30) | pdev->get_ReqCompletion(pdev));
	/** Fixme: Currently this is a FALSE bustime... */
	frames = GetTickCount();
	out = stream_create(4, InterfaceId, MessageId, IOCONTROL_COMPLETION, RequestId, 0);

	if (!out)
		return CHANNEL_RC_NO_MEMORY;

	Stream_Write_UINT32(out, frames);
	return stream_write_and_free(pdev, callback, out);
}

static UINT urbdrc_process_query_device_text(URBDRC_CHANNEL_CALLBACK* callback, wStream* in,
        UINT32 MessageId, IUDEVMAN* udevman, UINT32 UsbDevice)
{
	IUDEVICE* pdev;
	UINT32 InterfaceId;
	UINT32 TextType;
	UINT32 LocaleId;
	UINT32 bufferSize = 1024;
	wStream* out;
	BYTE DeviceDescription[bufferSize];
	WLog_DBG(TAG, "urbdrc_process_udev_data_transfer:"
	         " >>QUERY_DEVICE_TEXT<<");

	if (!callback || !in || !udevman)
		return CHANNEL_RC_BAD_CHANNEL;

	if (Stream_GetRemainingLength(in) < 8)
		return CHANNEL_RC_NULL_DATA;

	Stream_Read_UINT32(in, TextType);
	Stream_Read_UINT32(in, LocaleId);
	pdev = udevman->get_udevice_by_UsbDevice(udevman, UsbDevice);

	if (pdev == NULL)
		return 0;

	pdev->control_query_device_text(pdev, TextType, LocaleId, &bufferSize, DeviceDescription);
	InterfaceId = ((STREAM_ID_STUB << 30) | UsbDevice);
	out = stream_create_base(4 + bufferSize + 2, InterfaceId, MessageId, 0);

	if (!out)
		return CHANNEL_RC_NO_MEMORY;

	Stream_SetPosition(out, 8);

	if (bufferSize != 0)
	{
		Stream_Write_UINT32(out, (bufferSize / 2) + 1); /** cchDeviceDescription */
		Stream_Write(out, DeviceDescription, bufferSize);
		Stream_Write_UINT16(out, 0x0000);
	}
	else
		Stream_Write_UINT32(out, 0); /** cchDeviceDescription */

	Stream_Write_UINT32(out, 0); /** HResult */
	return stream_write_and_free(pdev, callback, out);
}

static void func_select_all_interface_for_msconfig(IUDEVICE* pdev,
        MSUSB_CONFIG_DESCRIPTOR* MsConfig)
{
	int inum;
	MSUSB_INTERFACE_DESCRIPTOR** MsInterfaces = MsConfig->MsInterfaces;
	BYTE  InterfaceNumber, AlternateSetting;
	UINT32 NumInterfaces = MsConfig->NumInterfaces;

	for (inum = 0; inum < NumInterfaces; inum++)
	{
		InterfaceNumber = MsInterfaces[inum]->InterfaceNumber;
		AlternateSetting = MsInterfaces[inum]->AlternateSetting;
		pdev->select_interface(pdev, InterfaceNumber, AlternateSetting);
	}
}

static UINT urb_select_configuration(URBDRC_CHANNEL_CALLBACK* callback, wStream* in,
                                     UINT32 MessageId, IUDEVMAN* udevman, UINT32 UsbDevice, UINT32 transferDir)
{
	MSUSB_CONFIG_DESCRIPTOR* MsConfig = NULL;
	IUDEVICE* pdev = NULL;
	UINT32 out_size, InterfaceId, RequestId, NumInterfaces, usbd_status = 0;
	BYTE ConfigurationDescriptorIsValid;
	wStream* out;
	int MsOutSize = 0, offset = 0;
	WLog_DBG(TAG, "URB_Func: URB_FUNCTION_SELECT_CONFIGURATION");

	if (!callback || !in || !udevman)
		return CHANNEL_RC_BAD_CHANNEL;

	if (transferDir == 0)
	{
		WLog_ERR(TAG,  "urb_select_configuration: not support transfer out");
		return CHANNEL_RC_NULL_DATA;
	}

	if (Stream_GetRemainingLength(in) < 9)
		return CHANNEL_RC_NULL_DATA;

	Stream_Read_UINT32(in, RequestId);
	Stream_Read_UINT8(in, ConfigurationDescriptorIsValid);
	Stream_Read_UINT32(in, NumInterfaces);
	pdev = udevman->get_udevice_by_UsbDevice(udevman, UsbDevice);

	if (pdev == NULL)
		return 0;

	InterfaceId = ((STREAM_ID_PROXY << 30) | pdev->get_ReqCompletion(pdev));
	offset = 12;

	/** if ConfigurationDescriptorIsValid is zero, then just do nothing.*/
	if (ConfigurationDescriptorIsValid)
	{
		/* parser data for struct config */
		MsConfig = msusb_msconfig_read(in, NumInterfaces);
		/* select config */
		pdev->select_configuration(pdev, MsConfig->bConfigurationValue);
		/* select all interface */
		func_select_all_interface_for_msconfig(pdev, MsConfig);
		/* complete configuration setup */
		MsConfig = pdev->complete_msconfig_setup(pdev, MsConfig);
	}

	if (MsConfig)
		MsOutSize = MsConfig->MsOutSize;

	if (MsOutSize > 0)
		out_size = 36 + MsOutSize;
	else
		out_size = 44;

	out = stream_create_base(out_size - 12, InterfaceId, MessageId, URB_COMPLETION_NO_DATA);

	if (!out)
		return CHANNEL_RC_NO_MEMORY;

	Stream_Write_UINT32(out, RequestId); /** RequestId */

	if (MsOutSize > 0)
	{
		/** CbTsUrbResult */
		Stream_Write_UINT32(out, 8 + MsOutSize);
		/** TS_URB_RESULT_HEADER Size*/
		Stream_Write_UINT16(out, 8 + MsOutSize);
	}
	else
	{
		Stream_Write_UINT32(out, 16);
		Stream_Write_UINT16(out, 16);
	}

	/** Padding, MUST be ignored upon receipt */
	Stream_Write_UINT16(out, URB_FUNCTION_SELECT_CONFIGURATION);
	Stream_Write_UINT32(out, usbd_status);	/** UsbdStatus */
	offset = 28;

	/** TS_URB_SELECT_CONFIGURATION_RESULT */
	if (MsOutSize > 0)
		msusb_msconfig_write(MsConfig, out);
	else
	{
		Stream_Write_UINT32(out, 0);	/** ConfigurationHandle */
		Stream_Write_UINT32(out, NumInterfaces);	/** NumInterfaces */
	}

	Stream_Write_UINT32(out, 0);	/** HResult */
	Stream_Write_UINT32(out, 0);	/** OutputBufferSize */
	return stream_write_and_free(pdev, callback, out);
}

static UINT urb_select_interface(URBDRC_CHANNEL_CALLBACK* callback, wStream* in,
                                 UINT32 MessageId, IUDEVMAN* udevman, UINT32 UsbDevice, UINT32 transferDir)
{
	MSUSB_CONFIG_DESCRIPTOR* MsConfig;
	MSUSB_INTERFACE_DESCRIPTOR* MsInterface;
	IUDEVICE* pdev;
	UINT32 InterfaceId, RequestId, ConfigurationHandle;
	UINT32 OutputBufferSize;
	BYTE InterfaceNumber;
	wStream* out;
	int interface_size;

	if (!callback || !in || !udevman)
		return CHANNEL_RC_BAD_CHANNEL;

	WLog_DBG(TAG, "URB_Func: URB_FUNCTION_SELECT_INTERFACE");

	if (transferDir == 0)
	{
		WLog_ERR(TAG,  "urb_select_interface: not support transfer out");
		return CHANNEL_RC_NULL_DATA;
	}

	if (Stream_GetRemainingLength(in) < 12)
		return CHANNEL_RC_NULL_DATA;

	pdev = udevman->get_udevice_by_UsbDevice(udevman, UsbDevice);

	if (pdev == NULL)
		return 0;

	InterfaceId = ((STREAM_ID_PROXY << 30) | pdev->get_ReqCompletion(pdev));
	Stream_Read_UINT32(in, RequestId);
	Stream_Read_UINT32(in, ConfigurationHandle);
	MsInterface = msusb_msinterface_read(in);

	if (!MsInterface || (Stream_GetRemainingLength(in) < 4))
		return CHANNEL_RC_NULL_DATA;

	Stream_Read_UINT32(in, OutputBufferSize);
	pdev->select_interface(pdev, MsInterface->InterfaceNumber, MsInterface->AlternateSetting);
	/* replace device's MsInterface */
	MsConfig = pdev->get_MsConfig(pdev);
	InterfaceNumber = MsInterface->InterfaceNumber;
	msusb_msinterface_replace(MsConfig, InterfaceNumber, MsInterface);
	/* complete configuration setup */
	MsConfig = pdev->complete_msconfig_setup(pdev, MsConfig);
	MsInterface = MsConfig->MsInterfaces[InterfaceNumber];
	interface_size = 16 + (MsInterface->NumberOfPipes * 20);
	out = stream_create_base(24 + interface_size, InterfaceId, MessageId, URB_COMPLETION_NO_DATA);

	if (!out)
		return CHANNEL_RC_NO_MEMORY;

	Stream_Write_UINT32(out, RequestId);	/** RequestId */
	Stream_Write_UINT32(out, 8 + interface_size);	/** CbTsUrbResult */
	/** TS_URB_RESULT_HEADER */
	Stream_Write_UINT16(out, 8 + interface_size);	/** Size */
	/** Padding, MUST be ignored upon receipt */
	Stream_Write_UINT16(out, URB_FUNCTION_SELECT_INTERFACE);
	Stream_Write_UINT32(out, USBD_STATUS_SUCCESS);	/** UsbdStatus */
	/** TS_URB_SELECT_INTERFACE_RESULT */
	msusb_msinterface_write(MsInterface, out);
	Stream_Write_UINT32(out, 0);	/** HResult */
	Stream_Write_UINT32(out, OutputBufferSize);	/** OutputBufferSize */
	return stream_write_and_free(pdev, callback, out);
}

static UINT urb_control_transfer(URBDRC_CHANNEL_CALLBACK* callback, wStream* in, UINT32 MessageId,
                                 IUDEVMAN* udevman, UINT32 UsbDevice, UINT32 transferDir,
                                 int External)
{
	IUDEVICE* pdev;
	UINT32 RequestId, InterfaceId, EndpointAddress, PipeHandle;
	UINT32 TransferFlags, OutputBufferSize, usbd_status, Timeout;
	BYTE bmRequestType, Request;
	UINT16 Value, Index, length;
	int ret;
	wStream* out;

	if (!callback || !in || !udevman)
		return CHANNEL_RC_BAD_CHANNEL;

	WLog_DBG(TAG, "URB_Func: URB_FUNCTION_CONTROL_TRANSFER_EX");

	if (Stream_GetRemainingLength(in) < 12)
		return CHANNEL_RC_NULL_DATA;

	Stream_Read_UINT32(in, RequestId);
	Stream_Read_UINT32(in, PipeHandle);
	Stream_Read_UINT32(in, TransferFlags); /** TransferFlags */

	switch (External)
	{
		case URB_CONTROL_TRANSFER_EXTERNAL:
			if (Stream_GetRemainingLength(in) < 4)
				return CHANNEL_RC_NULL_DATA;

			Stream_Read_UINT32(in, Timeout); /** TransferFlags */
			break;

		default:
		case URB_CONTROL_TRANSFER_NONEXTERNAL:
			break;
	}

	/** SetupPacket 8 bytes */
	if (Stream_GetRemainingLength(in) < 12)
		return CHANNEL_RC_NULL_DATA;

	Stream_Read_UINT8(in, bmRequestType);
	Stream_Read_UINT8(in, Request);
	Stream_Read_UINT16(in, Value);
	Stream_Read_UINT16(in, Index);
	Stream_Read_UINT16(in, length);
	Stream_Read_UINT32(in, OutputBufferSize);

	if (transferDir == USBD_TRANSFER_DIRECTION_OUT)
	{
		if (Stream_GetRemainingLength(in) < OutputBufferSize)
			return CHANNEL_RC_NULL_DATA;
	}

	pdev = udevman->get_udevice_by_UsbDevice(udevman, UsbDevice);

	if (pdev == NULL)
		return 0;

	InterfaceId = ((STREAM_ID_PROXY << 30) | pdev->get_ReqCompletion(pdev));
	EndpointAddress = (PipeHandle & 0x000000ff);
	Timeout = 2000;

	if (length != OutputBufferSize)
	{
		WLog_ERR(TAG, "urb_control_transfer ERROR: buf != length");
		return -1;
	}

	out = stream_create_base(24 + OutputBufferSize, InterfaceId, MessageId, 0);

	if (!out)
		return CHANNEL_RC_NO_MEMORY;

	Stream_SetPosition(out, 36);

	/** Get Buffer Data */
	if (transferDir == USBD_TRANSFER_DIRECTION_OUT)
		Stream_Write(out, Stream_Pointer(in), OutputBufferSize);

	Stream_SetPosition(out, 36);
	/**  process URB_FUNCTION_CONTROL_TRANSFER */
	ret = pdev->control_transfer(
	          pdev, RequestId, EndpointAddress, TransferFlags,
	          bmRequestType,
	          Request,
	          Value,
	          Index,
	          &usbd_status,
	          &OutputBufferSize,
	          Stream_Pointer(out),
	          Timeout);

	if (ret < 0)
	{
		WLog_DBG(TAG, "control_transfer: error num %d!!", ret);
		OutputBufferSize = 0;
	}

	/** send data */
	Stream_SetPosition(out, 8);

	if (transferDir == USBD_TRANSFER_DIRECTION_IN && OutputBufferSize != 0)
		Stream_Write_UINT32(out, URB_COMPLETION);	/** function id */
	else
		Stream_Write_UINT32(out, URB_COMPLETION_NO_DATA);

	Stream_Write_UINT32(out, RequestId);	/** RequestId */
	Stream_Write_UINT32(out, 0x00000008); 	/** CbTsUrbResult */
	/** TsUrbResult TS_URB_RESULT_HEADER */
	Stream_Write_UINT16(out, 0x0008);	/** Size */
	/** Padding, MUST be ignored upon receipt */
	Stream_Write_UINT16(out, URB_FUNCTION_CONTROL_TRANSFER);
	Stream_Write_UINT32(out, usbd_status);	/** UsbdStatus */
	Stream_Write_UINT32(out, 0);	/** HResult */
	Stream_Write_UINT32(out, OutputBufferSize);	/** OutputBufferSize */

	if (transferDir == USBD_TRANSFER_DIRECTION_IN)
		Stream_Seek(out, OutputBufferSize);

	return stream_write_and_free(pdev, callback, out);
}

static UINT urb_bulk_or_interrupt_transfer(URBDRC_CHANNEL_CALLBACK* callback, wStream* in,
        UINT32 MessageId, IUDEVMAN* udevman, UINT32 UsbDevice, UINT32 transferDir)
{
	BYTE* Buffer;
	IUDEVICE* pdev;
	wStream* out;
	UINT32 out_size = 24;
	UINT32 RequestId, InterfaceId, EndpointAddress, PipeHandle;
	UINT32 TransferFlags, OutputBufferSize, usbd_status = 0;

	if (!callback || !in || !udevman)
		return CHANNEL_RC_BAD_CHANNEL;

	if (Stream_GetRemainingLength(in) < 16)
		return CHANNEL_RC_NULL_DATA;

	Stream_Read_UINT32(in, RequestId);
	Stream_Read_UINT32(in, PipeHandle);
	Stream_Read_UINT32(in, TransferFlags);	/** TransferFlags */
	Stream_Read_UINT32(in, OutputBufferSize);
	pdev = udevman->get_udevice_by_UsbDevice(udevman, UsbDevice);

	if (pdev == NULL)
		return 0;

	InterfaceId = ((STREAM_ID_PROXY << 30) | pdev->get_ReqCompletion(pdev));
	EndpointAddress = (PipeHandle & 0x000000ff);

	if (transferDir == USBD_TRANSFER_DIRECTION_IN)
		out_size += OutputBufferSize;

	out = stream_create_base(out_size, InterfaceId, MessageId, 0);

	if (!out)
		return CHANNEL_RC_NO_MEMORY;

	Buffer = NULL;
	Stream_SetPosition(out, 36);

	switch (transferDir)
	{
		case USBD_TRANSFER_DIRECTION_OUT:
			Buffer = Stream_Pointer(in);
			break;

		case USBD_TRANSFER_DIRECTION_IN:
			Buffer = Stream_Pointer(out);
			break;
	}

	/**  process URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER */
	pdev->bulk_or_interrupt_transfer(
	    pdev, RequestId, EndpointAddress,
	    TransferFlags,
	    &usbd_status,
	    &OutputBufferSize,
	    Buffer,
	    10000);
	/** send data */
	Stream_SetPosition(out, 8);

	if (transferDir == USBD_TRANSFER_DIRECTION_IN && OutputBufferSize != 0)
		data_write_UINT32(out, URB_COMPLETION);	/** function id */
	else
		data_write_UINT32(out, URB_COMPLETION_NO_DATA);

	data_write_UINT32(out, RequestId);	/** RequestId */
	data_write_UINT32(out, 0x00000008);	/** CbTsUrbResult */
	/** TsUrbResult TS_URB_RESULT_HEADER */
	data_write_UINT16(out, 0x0008);	/** Size */
	/** Padding, MUST be ignored upon receipt */
	data_write_UINT16(out, URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER);
	data_write_UINT32(out, usbd_status);	/** UsbdStatus */
	data_write_UINT32(out, 0);	/** HResult */
	data_write_UINT32(out, OutputBufferSize);	/** OutputBufferSize */

	if (transferDir == USBD_TRANSFER_DIRECTION_IN)
		Stream_Seek(out, OutputBufferSize);

	return stream_write_and_free(pdev, callback, out);
}


static UINT urb_isoch_transfer(URBDRC_CHANNEL_CALLBACK* callback, wStream* in,
                               UINT32 MessageId,
                               IUDEVMAN* udevman,
                               UINT32 UsbDevice,
                               UINT32 transferDir)
{
	IUDEVICE* pdev;
	UINT32	RequestId, InterfaceId, EndpointAddress;
	UINT32	PipeHandle, TransferFlags, StartFrame, NumberOfPackets;
	UINT32	ErrorCount, OutputBufferSize, usbd_status = 0;
	UINT32	RequestField, noAck = 0;
	BYTE* 	iso_buffer	= NULL;
	BYTE* 	iso_packets	= NULL;
	wStream* out;
	int	nullBuffer = 0, iso_status;

	if (!callback || !in || !udevman)
		return CHANNEL_RC_BAD_CHANNEL;

	if (Stream_GetRemainingLength(in) < 24)
		return CHANNEL_RC_NULL_DATA;

	Stream_Read_UINT32(in, RequestField);
	RequestId			= RequestField & 0x7fffffff;
	noAck				= (RequestField & 0x80000000) >> 31;
	Stream_Read_UINT32(in, PipeHandle);
	EndpointAddress		= (PipeHandle & 0x000000ff);
	Stream_Read_UINT32(in, TransferFlags); /** TransferFlags */
	Stream_Read_UINT32(in, StartFrame); /** StartFrame */
	Stream_Read_UINT32(in, NumberOfPackets); /** NumberOfPackets */
	Stream_Read_UINT32(in, ErrorCount); /** ErrorCount */

	if (Stream_GetRemainingLength(in) < NumberOfPackets * 12 + 4)
		return CHANNEL_RC_NULL_DATA;

	Stream_Seek(in, NumberOfPackets * 12);
	Stream_Read_UINT32(in, OutputBufferSize);
	pdev = udevman->get_udevice_by_UsbDevice(udevman, UsbDevice);

	if (pdev == NULL)
		return 0;

	if (pdev->isSigToEnd(pdev))
		return 0;

	InterfaceId = ((STREAM_ID_PROXY << 30) | pdev->get_ReqCompletion(pdev));
	out = stream_create_base(36 + OutputBufferSize + (NumberOfPackets * 12), InterfaceId, MessageId, 0);

	if (!out)
		return CHANNEL_RC_NO_MEMORY;

	/** send data memory alloc */
	if (transferDir == USBD_TRANSFER_DIRECTION_OUT)
	{
		if (!noAck)
		{
			iso_packets = Stream_Buffer(out) + 40;
		}
	}
	else
	{
		iso_packets = Stream_Buffer(out) + 40;
	}

	switch (transferDir)
	{
		case USBD_TRANSFER_DIRECTION_OUT:
			/** Get Buffer Data */
			//memcpy(iso_buffer, data + offset, OutputBufferSize);
			iso_buffer = Stream_Pointer(out);
			break;

		case USBD_TRANSFER_DIRECTION_IN:
			iso_buffer = Stream_Buffer(out) + 48 + (NumberOfPackets * 12);
			break;
	}

	WLog_DBG(TAG, "urb_isoch_transfer: EndpointAddress: 0x%"PRIx32", "
	         "TransferFlags: 0x%"PRIx32", "
	         "StartFrame: 0x%"PRIx32", "
	         "NumberOfPackets: 0x%"PRIx32", "
	         "OutputBufferSize: 0x%"PRIx32" "
	         "RequestId: 0x%"PRIx32"",
	         EndpointAddress, TransferFlags, StartFrame,
	         NumberOfPackets, OutputBufferSize, RequestId);
#if ISOCH_FIFO
	ISOCH_CALLBACK_QUEUE* isoch_queue = NULL;
	ISOCH_CALLBACK_DATA* isoch = NULL;

	if (!noAck)
	{
		isoch_queue = (ISOCH_CALLBACK_QUEUE*)pdev->get_isoch_queue(pdev);
		isoch = isoch_queue->register_data(isoch_queue, callback, pdev);
	}

#endif
	iso_status = pdev->isoch_transfer(
	                 pdev, RequestId, EndpointAddress,
	                 TransferFlags,
	                 noAck,
	                 &ErrorCount,
	                 &usbd_status,
	                 &StartFrame,
	                 NumberOfPackets,
	                 iso_packets,
	                 &OutputBufferSize,
	                 iso_buffer,
	                 2000);

	if (noAck)
	{
		Stream_Free(out, TRUE);
		return 0;
	}

	if (iso_status < 0)
		nullBuffer = 1;

	if (nullBuffer)
		OutputBufferSize = 0;

	/* fill the send data */
	Stream_SetPosition(out, 8);

	if (OutputBufferSize != 0 && !nullBuffer)
		Stream_Write_UINT32(out, URB_COMPLETION);	/** function id */
	else
		Stream_Write_UINT32(out, URB_COMPLETION_NO_DATA);

	Stream_Write_UINT32(out, RequestId);	/** RequestId */
	Stream_Write_UINT32(out, 20 + (NumberOfPackets * 12));	/** CbTsUrbResult */
	/** TsUrbResult TS_URB_RESULT_HEADER */
	Stream_Write_UINT16(out, 20 + (NumberOfPackets * 12));	/** Size */
	/** Padding, MUST be ignored upon receipt */
	Stream_Write_UINT16(out, URB_FUNCTION_ISOCH_TRANSFER);
	Stream_Write_UINT32(out, usbd_status);	/** UsbdStatus */
	Stream_Write_UINT32(out, StartFrame);	/** StartFrame */

	if (!nullBuffer)
	{
		/** NumberOfPackets */
		Stream_Write_UINT32(out, NumberOfPackets);
		Stream_Write_UINT32(out, ErrorCount);	/** ErrorCount */
		Stream_Seek(out, (NumberOfPackets * 12));
	}
	else
	{
		Stream_Write_UINT32(out, 0);	/** NumberOfPackets */
		Stream_Write_UINT32(out, NumberOfPackets);	/** ErrorCount */
	}

	Stream_Write_UINT32(out, 0);	/** HResult */
	Stream_Write_UINT32(out, OutputBufferSize);	/** OutputBufferSize */
#if ISOCH_FIFO
	Stream_SealLength(out);

	if (!noAck)
	{
		pthread_mutex_lock(&isoch_queue->isoch_loading);
		isoch->out_data = Stream_Buffer(out);
		isoch->out_size = Stream_Length(out);
		pthread_mutex_unlock(&isoch_queue->isoch_loading);
	}

	if (nullBuffer)
		return -1;

	return 0;
#else
	return stream_write_and_free(pdev, callback, out);
#endif
}

static UINT urb_control_descriptor_request(URBDRC_CHANNEL_CALLBACK* callback,
        wStream* in,
        UINT32 MessageId,
        IUDEVMAN* udevman,
        UINT32 UsbDevice,
        BYTE func_recipient,
        UINT32 transferDir)
{
	IUDEVICE* pdev;
	UINT32 InterfaceId, RequestId, OutputBufferSize, usbd_status;
	BYTE bmRequestType, desc_index, desc_type;
	UINT16 langId;
	int ret;
	wStream* out;

	if (!callback || !in || !udevman)
		return CHANNEL_RC_BAD_CHANNEL;

	if (Stream_GetRemainingLength(in) < 12)
		return CHANNEL_RC_NULL_DATA;

	Stream_Read_UINT32(in, RequestId);
	Stream_Read_UINT8(in, desc_index);
	Stream_Read_UINT8(in, desc_type);
	Stream_Read_UINT16(in, langId);
	Stream_Read_UINT32(in, OutputBufferSize);
	pdev = udevman->get_udevice_by_UsbDevice(udevman, UsbDevice);

	if (pdev == NULL)
		return 0;

	InterfaceId = ((STREAM_ID_PROXY << 30) | pdev->get_ReqCompletion(pdev));
	out = stream_create(16 + OutputBufferSize, InterfaceId, MessageId, URB_COMPLETION, RequestId,
	                    0x00000008);

	if (!out)
		return CHANNEL_RC_NO_MEMORY;

	Stream_SetPosition(out, 36);
	bmRequestType = func_recipient;

	switch (transferDir)
	{
		case USBD_TRANSFER_DIRECTION_IN:
			bmRequestType |= 0x80;
			break;

		case USBD_TRANSFER_DIRECTION_OUT:
			bmRequestType |= 0x00;

			if (Stream_GetRemainingLength(in) < OutputBufferSize)
			{
				Stream_Free(out, TRUE);
				return CHANNEL_RC_NULL_DATA;
			}

			Stream_Write(out, Stream_Pointer(in), OutputBufferSize);
			break;

		default:
			WLog_DBG(TAG, "get error transferDir");
			OutputBufferSize = 0;
			usbd_status = USBD_STATUS_STALL_PID;
			break;
	}

	Stream_SetPosition(out, 36);
	/** process get usb device descriptor */
	ret = pdev->control_transfer(
	          pdev, RequestId, 0, 0, bmRequestType,
	          0x06, /* REQUEST_GET_DESCRIPTOR */
	          (desc_type << 8) | desc_index,
	          langId,
	          &usbd_status,
	          &OutputBufferSize,
	          Stream_Pointer(out),
	          1000);

	if (ret < 0)
	{
		WLog_DBG(TAG, "get_descriptor: error num %d", ret);
		OutputBufferSize = 0;
	}

	Stream_SetPosition(out, 20);
	/** TsUrbResult TS_URB_RESULT_HEADER */
	Stream_Write_UINT16(out, 0x0008);	/** Size */
	/** Padding, MUST be ignored upon receipt */
	Stream_Write_UINT16(out, URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE);
	Stream_Write_UINT32(out, usbd_status);	/** UsbdStatus */
	Stream_Write_UINT32(out, 0);	/** HResult */
	Stream_Write_UINT32(out, OutputBufferSize);	/** OutputBufferSize */
	Stream_Seek(out, OutputBufferSize);
	return stream_write_and_free(pdev, callback, out);
}

static UINT urb_control_get_status_request(URBDRC_CHANNEL_CALLBACK* callback, wStream* in,
        UINT32 MessageId,
        IUDEVMAN* udevman,
        UINT32 UsbDevice,
        BYTE func_recipient,
        UINT32 transferDir)
{
	IUDEVICE* pdev;
	UINT32 RequestId, InterfaceId, OutputBufferSize, usbd_status;
	UINT16 Index;
	BYTE bmRequestType;
	int ret;
	wStream* out;

	if (!callback || !in || !udevman)
		return CHANNEL_RC_BAD_CHANNEL;

	if (transferDir == 0)
	{
		WLog_DBG(TAG, "urb_control_get_status_request: not support transfer out");
		return -1;
	}

	if (Stream_GetRemainingLength(in) < 12)
		return CHANNEL_RC_NULL_DATA;

	Stream_Read_UINT32(in, RequestId);
	Stream_Read_UINT16(in, Index); /** Index */
	Stream_Seek_UINT16(in);
	Stream_Read_UINT32(in, OutputBufferSize);
	pdev = udevman->get_udevice_by_UsbDevice(udevman, UsbDevice);

	if (pdev == NULL)
		return 0;

	InterfaceId = ((STREAM_ID_PROXY << 30) | pdev->get_ReqCompletion(pdev));
	out = stream_create_base(24 + OutputBufferSize, InterfaceId, MessageId, 0);

	if (!out)
		return CHANNEL_RC_NO_MEMORY;

	Stream_SetPosition(out, 36);
	bmRequestType = func_recipient | 0x80;
	ret = pdev->control_transfer(
	          pdev, RequestId, 0, 0, bmRequestType,
	          0x00, /* REQUEST_GET_STATUS */
	          0,
	          Index,
	          &usbd_status,
	          &OutputBufferSize,
	          Stream_Pointer(out),
	          1000);

	if (ret < 0)
	{
		WLog_DBG(TAG, "control_transfer: error num %d!!", ret);
		OutputBufferSize = 0;
		usbd_status = USBD_STATUS_STALL_PID;
	}
	else
		usbd_status = USBD_STATUS_SUCCESS;

	/** send data */
	Stream_SetPosition(out, 8);

	if (transferDir == USBD_TRANSFER_DIRECTION_IN && OutputBufferSize != 0)
		Stream_Write_UINT32(out, URB_COMPLETION);	/** function id */
	else
		Stream_Write_UINT32(out, URB_COMPLETION_NO_DATA);

	Stream_Write_UINT32(out, RequestId);	/** RequestId, include NoAck*/
	Stream_Write_UINT32(out, 0x00000008);	/** CbTsUrbResult */
	/** TsUrbResult TS_URB_RESULT_HEADER */
	Stream_Write_UINT16(out, 0x0008);		/** Size */
	/** Padding, MUST be ignored upon receipt */
	Stream_Write_UINT16(out, URB_FUNCTION_VENDOR_DEVICE);
	Stream_Write_UINT32(out, usbd_status);	/** UsbdStatus */
	Stream_Write_UINT32(out, 0);	/** HResult */
	Stream_Write_UINT32(out, OutputBufferSize);	/** OutputBufferSize */

	if (transferDir == USBD_TRANSFER_DIRECTION_IN)
		Stream_Seek(out, OutputBufferSize);

	return stream_write_and_free(pdev, callback, out);
}

static UINT urb_control_vendor_or_class_request(URBDRC_CHANNEL_CALLBACK* callback,
        wStream* in,
        UINT32 MessageId,
        IUDEVMAN* udevman,
        UINT32 UsbDevice,
        BYTE func_type,
        BYTE func_recipient,
        UINT32 transferDir)
{
	IUDEVICE* pdev;
	UINT32 RequestId, InterfaceId, TransferFlags, usbd_status;
	UINT32 OutputBufferSize;
	BYTE ReqTypeReservedBits, Request, bmRequestType;
	UINT16 Value, Index, Padding;
	wStream* out;
	int ret;

	if (!callback || !in || !udevman)
		return CHANNEL_RC_BAD_CHANNEL;

	if (Stream_GetRemainingLength(in) < 20)
		return CHANNEL_RC_NULL_DATA;

	Stream_Read_UINT32(in, RequestId);
	Stream_Read_UINT32(in, TransferFlags); /** TransferFlags */
	Stream_Read_UINT8(in, ReqTypeReservedBits); /** ReqTypeReservedBids */
	Stream_Read_UINT8(in, Request); /** Request */
	Stream_Read_UINT16(in, Value); /** value */
	Stream_Read_UINT16(in, Index); /** index */
	Stream_Read_UINT16(in, Padding); /** Padding */
	Stream_Read_UINT32(in, OutputBufferSize);

	if (transferDir == USBD_TRANSFER_DIRECTION_OUT)
	{
		if (Stream_GetRemainingLength(in) < OutputBufferSize)
			return CHANNEL_RC_NULL_DATA;
	}

	/** control by vendor command */
	pdev = udevman->get_udevice_by_UsbDevice(udevman, UsbDevice);

	if (pdev == NULL)
		return 0;

	InterfaceId = ((STREAM_ID_PROXY << 30) | pdev->get_ReqCompletion(pdev));
	out = stream_create_base(24 + OutputBufferSize, InterfaceId, MessageId, 0);

	if (!out)
		return CHANNEL_RC_NO_MEMORY;

	Stream_SetPosition(out, 36);

	/** Get Buffer */
	if (transferDir == USBD_TRANSFER_DIRECTION_OUT)
		Stream_Write(out, Stream_Pointer(in), OutputBufferSize);

	/** vendor or class command */
	bmRequestType = func_type | func_recipient;

	if (TransferFlags & USBD_TRANSFER_DIRECTION)
		bmRequestType |= 0x80;

	WLog_DBG(TAG, "urb_control_vendor_or_class_request: "
	         "RequestId 0x%"PRIx32" TransferFlags: 0x%"PRIx32" ReqTypeReservedBits: 0x%"PRIx8" "
	         "Request:0x%"PRIx8" Value: 0x%"PRIx16" Index: 0x%"PRIx16" OutputBufferSize: 0x%"PRIx32" bmRequestType: 0x%"PRIx8"!!",
	         RequestId, TransferFlags, ReqTypeReservedBits, Request, Value,
	         Index, OutputBufferSize, bmRequestType);
	ret = pdev->control_transfer(
	          pdev, RequestId, 0, 0, bmRequestType,
	          Request,
	          Value,
	          Index,
	          &usbd_status,
	          &OutputBufferSize,
	          Stream_Pointer(out),
	          2000);

	if (ret < 0)
	{
		WLog_DBG(TAG, "control_transfer: error num %d!!", ret);
		OutputBufferSize = 0;
		usbd_status = USBD_STATUS_STALL_PID;
	}
	else
		usbd_status = USBD_STATUS_SUCCESS;

	/** send data */
	Stream_SetPosition(out, 8);
	Stream_Write_UINT32(out, InterfaceId);	/** interface */
	Stream_Write_UINT32(out, MessageId);	/** message id */

	if (transferDir == USBD_TRANSFER_DIRECTION_IN && OutputBufferSize != 0)
		Stream_Write_UINT32(out, URB_COMPLETION);	/** function id */
	else
		Stream_Write_UINT32(out, URB_COMPLETION_NO_DATA);

	Stream_Write_UINT32(out, RequestId);	/** RequestId, include NoAck*/
	Stream_Write_UINT32(out, 0x00000008);	/** CbTsUrbResult */
	/** TsUrbResult TS_URB_RESULT_HEADER */
	Stream_Write_UINT16(out, 0x0008);	/** Size */
	Stream_Write_UINT16(out,
	                    URB_FUNCTION_VENDOR_DEVICE);	/** Padding, MUST be ignored upon receipt */
	Stream_Write_UINT32(out, usbd_status);	/** UsbdStatus */
	Stream_Write_UINT32(out, 0);	/** HResult */
	Stream_Write_UINT32(out, OutputBufferSize);	/** OutputBufferSize */

	if (transferDir == USBD_TRANSFER_DIRECTION_IN)
		Stream_Seek(out, OutputBufferSize);

	return stream_write_and_free(pdev, callback, out);
}



static UINT urb_os_feature_descriptor_request(URBDRC_CHANNEL_CALLBACK* callback,
        wStream* in,
        UINT32 MessageId,
        IUDEVMAN* udevman,
        UINT32 UsbDevice,
        UINT32 transferDir)
{
	IUDEVICE* pdev;
	UINT32 RequestId, InterfaceId, OutputBufferSize, usbd_status;
	BYTE Recipient, InterfaceNumber, Ms_PageIndex;
	UINT16 Ms_featureDescIndex;
	UINT32 FunctionId;
	wStream* out;
	int ret;

	if (!callback || !in || !udevman)
		return CHANNEL_RC_BAD_CHANNEL;

	if (Stream_GetRemainingLength(in) < 16)
		return CHANNEL_RC_NULL_DATA;

	Stream_Read_UINT32(in, RequestId);
	Stream_Read_UINT8(in, Recipient); /** Recipient */
	Recipient = (Recipient & 0x1f); /* XXX: origin: Recipient && 0x1f !? */
	Stream_Read_UINT8(in, InterfaceNumber); /** InterfaceNumber */
	Stream_Read_UINT8(in, Ms_PageIndex); /** Ms_PageIndex */
	Stream_Read_UINT16(in, Ms_featureDescIndex); /** Ms_featureDescIndex */
	Stream_Seek(in, 3);
	Stream_Read_UINT32(in, OutputBufferSize);
	pdev = udevman->get_udevice_by_UsbDevice(udevman, UsbDevice);

	if (pdev == NULL)
		return 0;

	InterfaceId = ((STREAM_ID_PROXY << 30) | pdev->get_ReqCompletion(pdev));

	if (OutputBufferSize != 0)
		FunctionId = URB_COMPLETION;	/** function id */
	else
		FunctionId = URB_COMPLETION_NO_DATA;

	out = stream_create(16 + OutputBufferSize, InterfaceId, MessageId, FunctionId, RequestId,
	                    0x00000008);

	if (!out)
		return CHANNEL_RC_NO_MEMORY;

	Stream_SetPosition(out, 36);

	switch (transferDir)
	{
		case USBD_TRANSFER_DIRECTION_OUT:
			WLog_ERR(TAG,  "Function urb_os_feature_descriptor_request: OUT Unchecked");

			if (Stream_GetRemainingLength(in) < OutputBufferSize)
			{
				Stream_Free(out, TRUE);
				return CHANNEL_RC_NULL_DATA;
			}

			Stream_Write(out, Stream_Pointer(in), OutputBufferSize);
			break;

		case USBD_TRANSFER_DIRECTION_IN:
			break;
	}

	Stream_SetPosition(out, 36);
	WLog_DBG(TAG, "Ms descriptor arg: Recipient:0x%"PRIx8", "
	         "InterfaceNumber:0x%"PRIx8", Ms_PageIndex:0x%"PRIx8", "
	         "Ms_featureDescIndex:0x%"PRIx16", OutputBufferSize:0x%"PRIx32"",
	         Recipient, InterfaceNumber, Ms_PageIndex,
	         Ms_featureDescIndex, OutputBufferSize);
	/** get ms string */
	ret = pdev->os_feature_descriptor_request(
	          pdev, RequestId, Recipient,
	          InterfaceNumber,
	          Ms_PageIndex,
	          Ms_featureDescIndex,
	          &usbd_status,
	          &OutputBufferSize,
	          Stream_Pointer(out),
	          1000);

	if (ret < 0)
		WLog_DBG(TAG, "os_feature_descriptor_request: error num %d", ret);

	Stream_SetPosition(out, 20);
	/** TsUrbResult TS_URB_RESULT_HEADER */
	Stream_Write_UINT16(out, 0x0008);	/** Size */
	/** Padding, MUST be ignored upon receipt */
	Stream_Write_UINT16(out, URB_FUNCTION_GET_MS_FEATURE_DESCRIPTOR);
	Stream_Write_UINT32(out, usbd_status);	/** UsbdStatus */
	Stream_Write_UINT32(out, 0);	/** HResult */
	Stream_Write_UINT32(out, OutputBufferSize);	/** OutputBufferSize */
	Stream_Seek(out, OutputBufferSize);
	return stream_write_and_free(pdev, callback, out);
}

static UINT urb_pipe_request(URBDRC_CHANNEL_CALLBACK* callback, wStream* in,
                             UINT32 MessageId,
                             IUDEVMAN* udevman,
                             UINT32 UsbDevice,
                             UINT32 transferDir,
                             UINT32 action)
{
	IUDEVICE* pdev;
	UINT32 RequestId, InterfaceId, PipeHandle, EndpointAddress;
	UINT32 OutputBufferSize, usbd_status = 0;
	wStream* out;
	int ret;

	if (!callback || !in || !udevman)
		return CHANNEL_RC_BAD_CHANNEL;

	WLog_DBG(TAG, "URB_Func: URB_FUNCTION_ABORT_PIPE");

	if (transferDir == 0)
	{
		WLog_DBG(TAG, "urb_pipe_request: not support transfer out");
		return CHANNEL_RC_NULL_DATA;
	}

	if (Stream_GetRemainingLength(in) < 12)
		return CHANNEL_RC_NULL_DATA;

	Stream_Read_UINT32(in, RequestId);
	Stream_Read_UINT32(in, PipeHandle); /** PipeHandle */
	Stream_Read_UINT32(in, OutputBufferSize);
	pdev = udevman->get_udevice_by_UsbDevice(udevman, UsbDevice);

	if (pdev == NULL)
		return 0;

	InterfaceId = ((STREAM_ID_PROXY << 30) | pdev->get_ReqCompletion(pdev));
	EndpointAddress = (PipeHandle & 0x000000ff);

	switch (action)
	{
		case PIPE_CANCEL:
			WLog_DBG(TAG, "urb_pipe_request: PIPE_CANCEL 0x%"PRIx32"", EndpointAddress);
			ret = pdev->control_pipe_request(
			          pdev, RequestId, EndpointAddress,
			          &usbd_status,
			          PIPE_CANCEL);

			if (ret < 0)
			{
				WLog_DBG(TAG, "PIPE SET HALT: error num %d", ret);
			}

			break;

		case PIPE_RESET:
			WLog_DBG(TAG, "urb_pipe_request: PIPE_RESET ep 0x%"PRIx32"", EndpointAddress);
			ret = pdev->control_pipe_request(
			          pdev, RequestId, EndpointAddress,
			          &usbd_status,
			          PIPE_RESET);

			if (ret < 0)
				WLog_DBG(TAG, "PIPE RESET: error num %d!!", ret);

			break;

		default:
			WLog_DBG(TAG, "urb_pipe_request action: %d is not support!", action);
			break;
	}

	/** send data */
	out = stream_create(16, InterfaceId, MessageId, URB_COMPLETION_NO_DATA, RequestId, 0x00000008);

	if (!out)
		return CHANNEL_RC_NO_MEMORY;

	/** TsUrbResult TS_URB_RESULT_HEADER */
	Stream_Write_UINT16(out, 0x0008);	/** Size */
	/** Padding, MUST be ignored upon receipt */
	Stream_Write_UINT16(out, URB_FUNCTION_SYNC_RESET_PIPE_AND_CLEAR_STALL);
	Stream_Write_UINT32(out, usbd_status);	/** UsbdStatus */
	Stream_Write_UINT32(out, 0);	/** HResult */
	Stream_Write_UINT32(out, 0);	/** OutputBufferSize */
	return stream_write_and_free(pdev, callback, out);
}

static UINT urb_get_current_frame_number(URBDRC_CHANNEL_CALLBACK* callback,
        wStream* in,
        UINT32 MessageId,
        IUDEVMAN* udevman,
        UINT32 UsbDevice,
        UINT32 transferDir)
{
	IUDEVICE* pdev;
	UINT32 RequestId, InterfaceId, OutputBufferSize;
	UINT32 dummy_frames;
	wStream* out;

	if (!callback || !in || !udevman)
		return CHANNEL_RC_BAD_CHANNEL;

	if (transferDir == 0)
	{
		WLog_DBG(TAG, "urb_get_current_frame_number: not support transfer out");
		//exit(1);
		return CHANNEL_RC_NULL_DATA;
	}

	if (Stream_GetRemainingLength(in) < 8)
		return CHANNEL_RC_NULL_DATA;

	Stream_Read_UINT32(in, RequestId);
	Stream_Read_UINT32(in, OutputBufferSize);
	pdev = udevman->get_udevice_by_UsbDevice(udevman, UsbDevice);

	if (pdev == NULL)
		return 0;

	InterfaceId = ((STREAM_ID_PROXY << 30) | pdev->get_ReqCompletion(pdev));
	/** Fixme: Need to fill actual frame number!!*/
	dummy_frames = GetTickCount();
	out = stream_create_base(28, InterfaceId, MessageId, URB_COMPLETION_NO_DATA);

	if (!out)
		return CHANNEL_RC_NO_MEMORY;

	Stream_Write_UINT32(out, RequestId);	/** RequestId */
	Stream_Write_UINT32(out, 12);	/** CbTsUrbResult */
	/** TsUrbResult TS_URB_RESULT_HEADER */
	Stream_Write_UINT16(out, 12);	/** Size */
	/** Padding, MUST be ignored upon receipt */
	Stream_Write_UINT16(out, URB_FUNCTION_GET_CURRENT_FRAME_NUMBER);
	Stream_Write_UINT32(out, USBD_STATUS_SUCCESS);	/** UsbdStatus */
	Stream_Write_UINT32(out, dummy_frames);	/** FrameNumber */
	Stream_Write_UINT32(out, 0);	/** HResult */
	Stream_Write_UINT32(out, 0);	/** OutputBufferSize */
	return stream_write_and_free(pdev, callback, out);
}


/* Unused function for current server */
static UINT urb_control_get_configuration_request(URBDRC_CHANNEL_CALLBACK* callback,
        wStream* in,
        UINT32 MessageId,
        IUDEVMAN* udevman,
        UINT32 UsbDevice,
        UINT32 transferDir)
{
	IUDEVICE* pdev;
	UINT32 RequestId, InterfaceId, OutputBufferSize, usbd_status;
	wStream* out;
	int ret;

	if (!callback || !in || !udevman)
		return CHANNEL_RC_BAD_CHANNEL;

	if (Stream_GetRemainingLength(in) < 8)
		return CHANNEL_RC_NULL_DATA;

	Stream_Read_UINT32(in, RequestId);
	Stream_Read_UINT32(in, OutputBufferSize);

	if (transferDir == 0)
	{
		WLog_DBG(TAG, "urb_control_get_configuration_request:"
		         " not support transfer out");
		return -1;
	}

	pdev = udevman->get_udevice_by_UsbDevice(udevman, UsbDevice);

	if (pdev == NULL)
		return 0;

	InterfaceId = ((STREAM_ID_PROXY << 30) | pdev->get_ReqCompletion(pdev));
	out = stream_create_base(24 + OutputBufferSize, InterfaceId, MessageId, URB_COMPLETION);

	if (!out)
		return CHANNEL_RC_NO_MEMORY;

	Stream_SetPosition(out, 36);
	ret = pdev->control_transfer(
	          pdev, RequestId, 0, 0, 0x80 | 0x00,
	          0x08, /* REQUEST_GET_CONFIGURATION */
	          0,
	          0,
	          &usbd_status,
	          &OutputBufferSize,
	          Stream_Pointer(out),
	          1000);

	if (ret < 0)
	{
		WLog_DBG(TAG, "control_transfer: error num %d", ret);
		OutputBufferSize = 0;
	}

	Stream_SetPosition(out, 8);

	if (OutputBufferSize != 0)
		Stream_Write_UINT32(out, URB_COMPLETION);
	else
		Stream_Write_UINT32(out, URB_COMPLETION_NO_DATA);

	Stream_Write_UINT32(out, RequestId);	/** RequestId */
	Stream_Write_UINT32(out, 8);	/** CbTsUrbResult */
	/** TsUrbResult TS_URB_RESULT_HEADER */
	Stream_Write_UINT16(out, 8);	/** Size */
	/** Padding, MUST be ignored upon receipt */
	Stream_Write_UINT16(out, URB_FUNCTION_GET_CONFIGURATION);
	Stream_Write_UINT32(out, usbd_status);	/** UsbdStatus */
	Stream_Write_UINT32(out, 0);	/** HResult */
	Stream_Write_UINT32(out, OutputBufferSize);	/** OutputBufferSize */
	Stream_Seek(out, OutputBufferSize);
	return stream_write_and_free(pdev, callback, out);
}

/* Unused function for current server */
static UINT urb_control_get_interface_request(URBDRC_CHANNEL_CALLBACK* callback,
        wStream* in,
        UINT32 MessageId,
        IUDEVMAN* udevman,
        UINT32 UsbDevice,
        UINT32 transferDir)
{
	IUDEVICE* pdev;
	UINT32 RequestId, InterfaceId, OutputBufferSize, usbd_status;
	UINT16 interface;
	int ret;
	wStream* out;
	UINT32 FunctionId;

	if (!callback || !in || !udevman)
		return CHANNEL_RC_BAD_CHANNEL;

	if (transferDir == 0)
	{
		WLog_DBG(TAG, "urb_control_get_interface_request: not support transfer out");
		return CHANNEL_RC_NULL_DATA;
	}

	if (Stream_GetRemainingLength(in) < 10)
		return CHANNEL_RC_NULL_DATA;

	Stream_Read_UINT32(in, RequestId);
	Stream_Read_UINT16(in, interface);
	Stream_Seek_UINT16(in);
	Stream_Read_UINT32(in, OutputBufferSize);
	pdev = udevman->get_udevice_by_UsbDevice(udevman, UsbDevice);

	if (pdev == NULL)
		return 0;

	InterfaceId = ((STREAM_ID_PROXY << 30) | pdev->get_ReqCompletion(pdev));

	if (OutputBufferSize != 0)
		FunctionId = URB_COMPLETION;
	else
		FunctionId = URB_COMPLETION_NO_DATA;

	out = stream_create_base(24 + OutputBufferSize, InterfaceId, MessageId, FunctionId);

	if (!out)
		return CHANNEL_RC_NO_MEMORY;

	Stream_Write_UINT32(out, RequestId); /** RequestId */
	Stream_Write_UINT32(out, 8); /** CbTsUrbResult */
	/** TsUrbResult TS_URB_RESULT_HEADER */
	Stream_Write_UINT16(out, 8); /** Size */
	Stream_Write_UINT16(out, URB_FUNCTION_GET_INTERFACE);
	Stream_Write_UINT32(out, usbd_status);
	Stream_Write_UINT32(out, 0);	/** HResult */
	Stream_Write_UINT32(out, OutputBufferSize);	/** OutputBufferSize */
	ret = pdev->control_transfer(pdev, RequestId, 0, 0, 0x80 | 0x01,
	                             0x0A, /* REQUEST_GET_INTERFACE */
	                             0,
	                             interface,
	                             &usbd_status,
	                             &OutputBufferSize,
	                             Stream_Pointer(out),
	                             1000);

	if (ret < 0)
	{
		WLog_DBG(TAG, "control_transfer: error num %d", ret);
		OutputBufferSize = 0;
	}

	Stream_Seek(out, OutputBufferSize);
	return stream_write_and_free(pdev, callback, out);
}

static UINT urb_control_feature_request(URBDRC_CHANNEL_CALLBACK* callback, wStream* in,
                                        UINT32 MessageId,
                                        IUDEVMAN* udevman,
                                        UINT32 UsbDevice,
                                        BYTE func_recipient,
                                        BYTE command,
                                        UINT32 transferDir)
{
	IUDEVICE* pdev;
	UINT32 RequestId, InterfaceId, OutputBufferSize, usbd_status;
	UINT16 FeatureSelector, Index;
	BYTE bmRequestType, bmRequest;
	BYTE* buffer;
	wStream* out;
	int ret;
	UINT32 FunctionId;
	size_t pos;

	if (!callback || !in || !udevman)
		return CHANNEL_RC_BAD_CHANNEL;

	if (Stream_GetRemainingLength(in) < 12)
		return CHANNEL_RC_NULL_DATA;

	Stream_Read_UINT32(in, RequestId);
	Stream_Read_UINT16(in, FeatureSelector);
	Stream_Read_UINT16(in, Index);
	Stream_Read_UINT32(in, OutputBufferSize);
	pdev = udevman->get_udevice_by_UsbDevice(udevman, UsbDevice);

	if (pdev == NULL)
		return 0;

	InterfaceId = ((STREAM_ID_PROXY << 30) | pdev->get_ReqCompletion(pdev));

	if (OutputBufferSize != 0)
		FunctionId = URB_COMPLETION;
	else
		FunctionId = URB_COMPLETION_NO_DATA;

	out = stream_create_base(24 + OutputBufferSize, InterfaceId, MessageId, FunctionId);

	if (!out)
		return CHANNEL_RC_NO_MEMORY;

	Stream_Write_UINT32(out, RequestId);
	Stream_Write_UINT32(out, 8); /** CbTsUrbResult */
	Stream_Write_UINT16(out, 8);
	Stream_Write_UINT16(out, URB_FUNCTION_GET_INTERFACE);
	buffer = Stream_Pointer(out);
	bmRequestType = func_recipient;

	switch (transferDir)
	{
		case USBD_TRANSFER_DIRECTION_OUT:
			WLog_ERR(TAG,  "Function urb_control_feature_request: OUT Unchecked");

			if (Stream_GetRemainingLength(in) < OutputBufferSize)
			{
				Stream_Free(out, TRUE);
				return CHANNEL_RC_NULL_DATA;
			}

			Stream_Write(out, Stream_Pointer(in), OutputBufferSize);
			bmRequestType |= 0x00;
			break;

		case USBD_TRANSFER_DIRECTION_IN:
			bmRequestType |= 0x80;
			break;
	}

	switch (command)
	{
		case URB_SET_FEATURE:
			bmRequest = 0x03; /* REQUEST_SET_FEATURE */
			break;

		case URB_CLEAR_FEATURE:
			bmRequest = 0x01; /* REQUEST_CLEAR_FEATURE */
			break;

		default:
			WLog_ERR(TAG,  "urb_control_feature_request: Error Command 0x%02"PRIx8"", command);
			Stream_Free(out, TRUE);
			return -1;
	}

	ret = pdev->control_transfer(
	          pdev, RequestId, 0, 0, bmRequestType, bmRequest,
	          FeatureSelector,
	          Index,
	          &usbd_status,
	          &OutputBufferSize,
	          buffer,
	          1000);

	if (ret < 0)
	{
		WLog_DBG(TAG, "feature control transfer: error num %d", ret);
		OutputBufferSize = 0;
	}

	pos = Stream_GetPosition(out);
	Stream_SetPosition(out, 24);
	Stream_Write_UINT32(out, usbd_status);
	Stream_Write_UINT32(out, 0); /** HResult */
	Stream_Write_UINT32(out, OutputBufferSize);
	Stream_SetPosition(out, pos);
	return stream_write_and_free(pdev, callback, out);
}

static int urbdrc_process_transfer_request(URBDRC_CHANNEL_CALLBACK* callback, wStream* in,
        UINT32 MessageId,
        IUDEVMAN* udevman,
        UINT32 UsbDevice,
        UINT32 transferDir)
{
	IUDEVICE* 	pdev;
	UINT32		CbTsUrb;
	UINT16		Size;
	UINT16		URB_Function;
	UINT32		OutputBufferSize;
	UINT			error = 0;
	WLog_DBG(TAG, "urbdrc_process_udev_data_transfer:"
	         " >>TRANSFER_OUT_REQUEST<<0x%"PRIX32"", transferDir);

	if (!callback || !in || !udevman)
		return CHANNEL_RC_BAD_CHANNEL;

	if (Stream_GetRemainingLength(in) < 12)
		return CHANNEL_RC_NULL_DATA;

	Stream_Read_UINT32(in, CbTsUrb);	/** CbTsUrb */
	Stream_Read_UINT16(in, Size);	/** size */

	if (Stream_GetRemainingLength(in) < CbTsUrb + 4)
		return CHANNEL_RC_NULL_DATA;

	Stream_Read_UINT32(in, URB_Function);
	Stream_Seek(in, CbTsUrb - 4);
	Stream_Read_UINT32(in, OutputBufferSize);
	pdev = udevman->get_udevice_by_UsbDevice(udevman, UsbDevice);

	if (pdev == NULL)
		return 0;

	switch (URB_Function)
	{
		case URB_FUNCTION_SELECT_CONFIGURATION:			/** 0x0000 */
			error = urb_select_configuration(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            transferDir);
			break;

		case URB_FUNCTION_SELECT_INTERFACE:				/** 0x0001 */
			error = urb_select_interface(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            transferDir);
			break;

		case URB_FUNCTION_ABORT_PIPE:					/** 0x0002  */
			error = urb_pipe_request(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            transferDir,
			            PIPE_CANCEL);
			break;

		case URB_FUNCTION_TAKE_FRAME_LENGTH_CONTROL:	/** 0x0003  */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_TAKE_FRAME_LENGTH_CONTROL");
			error = -1;  /** This URB function is obsolete in Windows 2000
							 * and later operating systems
							 * and is not supported by Microsoft. */
			break;

		case URB_FUNCTION_RELEASE_FRAME_LENGTH_CONTROL:	/** 0x0004 */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_RELEASE_FRAME_LENGTH_CONTROL");
			error = -1;  /** This URB function is obsolete in Windows 2000
							 * and later operating systems
							 * and is not supported by Microsoft. */
			break;

		case URB_FUNCTION_GET_FRAME_LENGTH:				/** 0x0005 */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_GET_FRAME_LENGTH");
			error = -1;  /** This URB function is obsolete in Windows 2000
							 * and later operating systems
							 * and is not supported by Microsoft. */
			break;

		case URB_FUNCTION_SET_FRAME_LENGTH:				/** 0x0006 */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_SET_FRAME_LENGTH");
			error = -1;  /** This URB function is obsolete in Windows 2000
							 * and later operating systems
							 * and is not supported by Microsoft. */
			break;

		case URB_FUNCTION_GET_CURRENT_FRAME_NUMBER:		/** 0x0007 */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_GET_CURRENT_FRAME_NUMBER");
			error = urb_get_current_frame_number(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            transferDir);
			break;

		case URB_FUNCTION_CONTROL_TRANSFER:				/** 0x0008 */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_CONTROL_TRANSFER");
			error = urb_control_transfer(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            transferDir,
			            URB_CONTROL_TRANSFER_NONEXTERNAL);
			break;

		case URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER:	/** 0x0009 */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER");
			error = urb_bulk_or_interrupt_transfer(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            transferDir);
			break;

		case URB_FUNCTION_ISOCH_TRANSFER:				/** 0x000A */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_ISOCH_TRANSFER");
			error = urb_isoch_transfer(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            transferDir);
			break;

		case URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE:	/** 0x000B */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE");
			error = urb_control_descriptor_request(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            0x00,
			            transferDir);
			break;

		case URB_FUNCTION_SET_DESCRIPTOR_TO_DEVICE:		/** 0x000C */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_SET_DESCRIPTOR_TO_DEVICE");
			error = urb_control_descriptor_request(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            0x00,
			            transferDir);
			break;

		case URB_FUNCTION_SET_FEATURE_TO_DEVICE:		/** 0x000D */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_SET_FEATURE_TO_DEVICE");
			error = urb_control_feature_request(callback,
			                                    in,
			                                    MessageId,
			                                    udevman,
			                                    UsbDevice,
			                                    0x00,
			                                    URB_SET_FEATURE,
			                                    transferDir);
			break;

		case URB_FUNCTION_SET_FEATURE_TO_INTERFACE:		/** 0x000E */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_SET_FEATURE_TO_INTERFACE");
			error = urb_control_feature_request(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            0x01,
			            URB_SET_FEATURE,
			            transferDir);
			break;

		case URB_FUNCTION_SET_FEATURE_TO_ENDPOINT:		/** 0x000F */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_SET_FEATURE_TO_ENDPOINT");
			error = urb_control_feature_request(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            0x02,
			            URB_SET_FEATURE,
			            transferDir);
			break;

		case URB_FUNCTION_CLEAR_FEATURE_TO_DEVICE:		/** 0x0010 */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_CLEAR_FEATURE_TO_DEVICE");
			error = urb_control_feature_request(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            0x00,
			            URB_CLEAR_FEATURE,
			            transferDir);
			break;

		case URB_FUNCTION_CLEAR_FEATURE_TO_INTERFACE:	/** 0x0011 */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_CLEAR_FEATURE_TO_INTERFACE");
			error = urb_control_feature_request(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            0x01,
			            URB_CLEAR_FEATURE,
			            transferDir);
			break;

		case URB_FUNCTION_CLEAR_FEATURE_TO_ENDPOINT:	/** 0x0012 */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_CLEAR_FEATURE_TO_ENDPOINT");
			error = urb_control_feature_request(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            0x02,
			            URB_CLEAR_FEATURE,
			            transferDir);
			break;

		case URB_FUNCTION_GET_STATUS_FROM_DEVICE:		/** 0x0013 */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_GET_STATUS_FROM_DEVICE");
			error = urb_control_get_status_request(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            0x00,
			            transferDir);
			break;

		case URB_FUNCTION_GET_STATUS_FROM_INTERFACE:	/** 0x0014 */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_GET_STATUS_FROM_INTERFACE");
			error = urb_control_get_status_request(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            0x01,
			            transferDir);
			break;

		case URB_FUNCTION_GET_STATUS_FROM_ENDPOINT:		/** 0x0015 */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_GET_STATUS_FROM_ENDPOINT");
			error = urb_control_get_status_request(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            0x02,
			            transferDir);
			break;

		case URB_FUNCTION_RESERVED_0X0016:				/** 0x0016 */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_RESERVED_0X0016");
			error = -1;
			break;

		case URB_FUNCTION_VENDOR_DEVICE:				/** 0x0017 */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_VENDOR_DEVICE");
			error = urb_control_vendor_or_class_request(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            (0x02 << 5), /* vendor type */
			            0x00,
			            transferDir);
			break;

		case URB_FUNCTION_VENDOR_INTERFACE:				/** 0x0018 */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_VENDOR_INTERFACE");
			error = urb_control_vendor_or_class_request(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            (0x02 << 5), /* vendor type */
			            0x01,
			            transferDir);
			break;

		case URB_FUNCTION_VENDOR_ENDPOINT:				/** 0x0019 */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_VENDOR_ENDPOINT");
			error = urb_control_vendor_or_class_request(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            (0x02 << 5), /* vendor type */
			            0x02,
			            transferDir);
			break;

		case URB_FUNCTION_CLASS_DEVICE:					/** 0x001A */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_CLASS_DEVICE");
			error = urb_control_vendor_or_class_request(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            (0x01 << 5), /* class type */
			            0x00,
			            transferDir);
			break;

		case URB_FUNCTION_CLASS_INTERFACE:				/** 0x001B */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_CLASS_INTERFACE");
			error = urb_control_vendor_or_class_request(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            (0x01 << 5), /* class type */
			            0x01,
			            transferDir);
			break;

		case URB_FUNCTION_CLASS_ENDPOINT:				/** 0x001C */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_CLASS_ENDPOINT");
			error = urb_control_vendor_or_class_request(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            (0x01 << 5), /* class type */
			            0x02,
			            transferDir);
			break;

		case URB_FUNCTION_RESERVE_0X001D:				/** 0x001D */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_RESERVE_0X001D");
			error = -1;
			break;

		case URB_FUNCTION_SYNC_RESET_PIPE_AND_CLEAR_STALL: /** 0x001E */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_SYNC_RESET_PIPE_AND_CLEAR_STALL");
			error = urb_pipe_request(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            transferDir,
			            PIPE_RESET);
			break;

		case URB_FUNCTION_CLASS_OTHER:					/** 0x001F */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_CLASS_OTHER");
			error = urb_control_vendor_or_class_request(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            (0x01 << 5), /* class type */
			            0x03,
			            transferDir);
			break;

		case URB_FUNCTION_VENDOR_OTHER:					/** 0x0020 */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_VENDOR_OTHER");
			error = urb_control_vendor_or_class_request(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            (0x02 << 5), /* vendor type */
			            0x03,
			            transferDir);
			break;

		case URB_FUNCTION_GET_STATUS_FROM_OTHER:		/** 0x0021 */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_GET_STATUS_FROM_OTHER");
			error = urb_control_get_status_request(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            0x03,
			            transferDir);
			break;

		case URB_FUNCTION_CLEAR_FEATURE_TO_OTHER:		/** 0x0022 */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_CLEAR_FEATURE_TO_OTHER");
			error = urb_control_feature_request(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            0x03,
			            URB_CLEAR_FEATURE,
			            transferDir);
			break;

		case URB_FUNCTION_SET_FEATURE_TO_OTHER:			/** 0x0023 */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_SET_FEATURE_TO_OTHER");
			error = urb_control_feature_request(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            0x03,
			            URB_SET_FEATURE,
			            transferDir);
			break;

		case URB_FUNCTION_GET_DESCRIPTOR_FROM_ENDPOINT:	/** 0x0024 */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_GET_DESCRIPTOR_FROM_ENDPOINT");
			error = urb_control_descriptor_request(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            0x02,
			            transferDir);
			break;

		case URB_FUNCTION_SET_DESCRIPTOR_TO_ENDPOINT:	/** 0x0025 */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_SET_DESCRIPTOR_TO_ENDPOINT");
			error = urb_control_descriptor_request(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            0x02,
			            transferDir);
			break;

		case URB_FUNCTION_GET_CONFIGURATION:			/** 0x0026 */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_GET_CONFIGURATION");
			error =  urb_control_get_configuration_request(
			             callback, in,
			             MessageId,
			             udevman,
			             UsbDevice,
			             transferDir);
			break;

		case URB_FUNCTION_GET_INTERFACE:				/** 0x0027 */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_GET_INTERFACE");
			error =  urb_control_get_interface_request(
			             callback, in,
			             MessageId,
			             udevman,
			             UsbDevice,
			             transferDir);
			break;

		case URB_FUNCTION_GET_DESCRIPTOR_FROM_INTERFACE:	/** 0x0028 */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_GET_DESCRIPTOR_FROM_INTERFACE");
			error = urb_control_descriptor_request(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            0x01,
			            transferDir);
			break;

		case URB_FUNCTION_SET_DESCRIPTOR_TO_INTERFACE:	/** 0x0029 */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_SET_DESCRIPTOR_TO_INTERFACE");
			error = urb_control_descriptor_request(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            0x01,
			            transferDir);
			break;

		case URB_FUNCTION_GET_MS_FEATURE_DESCRIPTOR:	/** 0x002A */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_GET_MS_FEATURE_DESCRIPTOR");
			error = urb_os_feature_descriptor_request(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            transferDir);
			break;

		case URB_FUNCTION_RESERVE_0X002B:				/** 0x002B */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_RESERVE_0X002B");
			error = -1;
			break;

		case URB_FUNCTION_RESERVE_0X002C:				/** 0x002C */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_RESERVE_0X002C");
			error = -1;
			break;

		case URB_FUNCTION_RESERVE_0X002D:				/** 0x002D */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_RESERVE_0X002D");
			error = -1;
			break;

		case URB_FUNCTION_RESERVE_0X002E:				/** 0x002E */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_RESERVE_0X002E");
			error = -1;
			break;

		case URB_FUNCTION_RESERVE_0X002F:				/** 0x002F */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_RESERVE_0X002F");
			error = -1;
			break;

		/** USB 2.0 calls start at 0x0030 */
		case URB_FUNCTION_SYNC_RESET_PIPE:				/** 0x0030 */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_SYNC_RESET_PIPE");
			error = urb_pipe_request(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            transferDir,
			            PIPE_RESET);
			error = -9;  /** function not support */
			break;

		case URB_FUNCTION_SYNC_CLEAR_STALL:				/** 0x0031 */
			WLog_DBG(TAG, "URB_Func: URB_FUNCTION_SYNC_CLEAR_STALL");
			error = urb_pipe_request(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            transferDir,
			            PIPE_RESET);
			error = -9;
			break;

		case URB_FUNCTION_CONTROL_TRANSFER_EX:			/** 0x0032 */
			error = urb_control_transfer(
			            callback, in,
			            MessageId,
			            udevman,
			            UsbDevice,
			            transferDir,
			            URB_CONTROL_TRANSFER_EXTERNAL);
			break;

		default:
			WLog_DBG(TAG, "URB_Func: %"PRIx16" is not found!", URB_Function);
			break;
	}

	return error;
}

void* urbdrc_process_udev_data_transfer(void* arg)
{
	TRANSFER_DATA*  transfer_data = (TRANSFER_DATA*) arg;
	URBDRC_CHANNEL_CALLBACK* callback = transfer_data->callback;
	wStream* 	pData		= transfer_data->pData;
	UINT32		UsbDevice	= transfer_data->UsbDevice;
	IUDEVMAN* 	udevman		= transfer_data->udevman;
	UINT32		MessageId;
	UINT32		FunctionId;
	IUDEVICE*   pdev;
	UINT error = CHANNEL_RC_OK;
	pdev = udevman->get_udevice_by_UsbDevice(udevman, UsbDevice);

	if (pdev == NULL || pdev->isSigToEnd(pdev) || !pData)
	{
		if (transfer_data)
		{
			Stream_Free(pData, TRUE);
			zfree(transfer_data);
		}

		return NULL;
	}

	if (Stream_GetRemainingLength(pData) < 4)
	{
		if (transfer_data)
		{
			Stream_Free(pData, TRUE);
			zfree(transfer_data);
		}
	}

	pdev->push_action(pdev);
	/* USB kernel driver detach!! */
	pdev->detach_kernel_driver(pdev);
	Stream_Read_UINT32(pData, MessageId);
	Stream_Read_UINT32(pData, FunctionId);

	switch (FunctionId)
	{
		case CANCEL_REQUEST:
			error = urbdrc_process_cancel_request(
			            pData,
			            udevman,
			            UsbDevice);
			break;

		case REGISTER_REQUEST_CALLBACK:
			error = urbdrc_process_register_request_callback(
			            callback,
			            pData,
			            udevman,
			            UsbDevice);
			break;

		case IO_CONTROL:
			error = urbdrc_process_io_control(
			            callback,
			            pData,
			            MessageId,
			            udevman, UsbDevice);
			break;

		case INTERNAL_IO_CONTROL:
			error = urbdrc_process_internal_io_control(
			            callback,
			            pData,
			            MessageId,
			            udevman, UsbDevice);
			break;

		case QUERY_DEVICE_TEXT:
			error = urbdrc_process_query_device_text(
			            callback,
			            pData,
			            MessageId,
			            udevman,
			            UsbDevice);
			break;

		case TRANSFER_IN_REQUEST:
			error = urbdrc_process_transfer_request(
			            callback,
			            pData,
			            MessageId,
			            udevman,
			            UsbDevice,
			            USBD_TRANSFER_DIRECTION_IN);
			break;

		case TRANSFER_OUT_REQUEST:
			error = urbdrc_process_transfer_request(
			            callback,
			            pData,
			            MessageId,
			            udevman,
			            UsbDevice,
			            USBD_TRANSFER_DIRECTION_OUT);
			break;

		case RETRACT_DEVICE:
			error = urbdrc_process_retract_device_request(
			            pData,
			            udevman,
			            UsbDevice);
			break;

		default:
			WLog_DBG(TAG, "urbdrc_process_udev_data_transfer:"
			         " unknown FunctionId 0x%"PRIX32"", FunctionId);
			error = -1;
			break;
	}

	if (pdev)
	{
#if ISOCH_FIFO
		/* check isochronous fds */
		func_check_isochronous_fds(pdev);
#endif
		/* close this channel, if device is not found. */
		pdev->complete_action(pdev);
	}

	udevman->push_urb(udevman);

	if (transfer_data)
	{
		Stream_Free(pData, TRUE);
		free(transfer_data);
	}

	return NULL;
}
