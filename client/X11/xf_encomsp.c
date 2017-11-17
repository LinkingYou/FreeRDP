/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * X11 RAIL
 *
 * Copyright 2013 Marc-Andre Moreau <marcandre.moreau@gmail.com>
 * Copyright 2013 Corey Clayton <can.of.tuna@gmail.com>
 * Copyright 2014 Thincast Technologies GmbH
 * Copyright 2014 Norbert Federa <norbert.federa@thincast.com>
 * Copyright 2016 Armin Novak <armin.novak@thincast.com>
 * Copyright 2016 Thincast Technologies GmbH
 * Copyright 2017 Armin Novak <armin.novak@thincast.com>
 * Copyright 2017 Thincast Technologies GmbH
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <X11/Xlib.h>
#include <X11/Xutil.h>

#include <winpr/wlog.h>
#include <winpr/print.h>

#include <freerdp/client/encomsp.h>

#include "xf_window.h"
#include "xf_encomsp.h"

#define TAG CLIENT_TAG("x11")

void xf_encomsp_toggle_control(xfContext* xfc)
{
	EncomspClientContext* encomsp;
	ENCOMSP_CHANGE_PARTICIPANT_CONTROL_LEVEL_PDU pdu;
	encomsp = xfc->encomsp;

	if (!encomsp)
		return;

	pdu.ParticipantId = 0;
	pdu.Flags = ENCOMSP_REQUEST_VIEW;

	if (!xfc->controlToggle)
		pdu.Flags |= ENCOMSP_REQUEST_INTERACT;

	encomsp->ChangeParticipantControlLevel(encomsp, &pdu);
	xfc->controlToggle = !xfc->controlToggle;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT xf_encomsp_participant_created(EncomspClientContext* context,
        ENCOMSP_PARTICIPANT_CREATED_PDU* participantCreated)
{
	return CHANNEL_RC_OK;
}

void xf_encomsp_init(xfContext* xfc, EncomspClientContext* encomsp)
{
	xfc->encomsp = encomsp;
	encomsp->custom = (void*) xfc;
	encomsp->ParticipantCreated = xf_encomsp_participant_created;
}

void xf_encomsp_uninit(xfContext* xfc, EncomspClientContext* encomsp)
{
	xfc->encomsp = NULL;
}

