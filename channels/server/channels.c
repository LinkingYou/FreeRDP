/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Server Channels
 *
 * Copyright 2011-2012 Vic Lee
 * Copyright 2012 Marc-Andre Moreau <marcandre.moreau@gmail.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <freerdp/constants.h>
#include <freerdp/server/channels.h>

#include <winpr/crt.h>
#include <winpr/synch.h>
#include <winpr/stream.h>

#include "channels.h"

/**
 * this is a workaround to force importing symbols
 * will need to fix that later on cleanly
 */
#if defined(CHANNEL_AUDIN_SERVER)
#include <freerdp/server/audin.h>
#endif
#if defined(CHANNEL_RDPSND_SERVER)
#include <freerdp/server/rdpsnd.h>
#endif
#if defined(CHANNEL_CLIPRDR_SERVER)
#include <freerdp/server/cliprdr.h>
#endif
#if defined(CHANNEL_ECHO_SERVER)
#include <freerdp/server/echo.h>
#endif
#if defined(CHANNEL_RDPDR_SERVER)
#include <freerdp/server/rdpdr.h>
#endif
#if defined(CHANNEL_RDPEI_SERVER)
#include <freerdp/server/rdpei.h>
#endif
#if defined(CHANNEL_DRDYNVC_SERVER)
#include <freerdp/server/drdynvc.h>
#endif
#if defined(CHANNEL_REMDESK_SERVER)
#include <freerdp/server/remdesk.h>
#endif
#if defined(CHANNEL_ENCOMSP_SERVER)
#include <freerdp/server/encomsp.h>
#endif
#if defined(CHANNEL_RDPGFX_SERVER)
#include <freerdp/server/rdpgfx.h>
#endif

void freerdp_channels_dummy(void)
{
#if defined(CHANNEL_AUDIN_SERVER)
	audin_server_context_new(NULL);
	audin_server_context_free(NULL);
#endif
#if defined(CHANNEL_RDPSND_SERVER)
	rdpsnd_server_context_new(NULL);
	rdpsnd_server_context_free(NULL);
#endif
#if defined(CHANNEL_CLIPRDR_SERVER)
	cliprdr_server_context_new(NULL);
	cliprdr_server_context_free(NULL);
#endif
#if defined(CHANNEL_ECHO_SERVER)
	echo_server_context_new(NULL);
	echo_server_context_free(NULL);
#endif
#if defined(CHANNEL_RDPDR_SERVER)
	rdpdr_server_context_new(NULL);
	rdpdr_server_context_free(NULL);
#endif
#if defined(CHANNEL_DRDYNVC_SERVER)
	drdynvc_server_context_new(NULL);
	drdynvc_server_context_free(NULL);
#endif
#if defined(CHANNEL_RDPEI_SERVER)
	rdpei_server_context_new(NULL);
	rdpei_server_context_free(NULL);
#endif
#if defined(CHANNEL_REMDESK_SERVER)
	remdesk_server_context_new(NULL);
	remdesk_server_context_free(NULL);
#endif
#if defined(CHANNEL_ENCOMSP_SERVER)
	encomsp_server_context_new(NULL);
	encomsp_server_context_free(NULL);
#endif
#if defined(CHANNEL_RDPGFX_SERVER)
	rdpgfx_server_context_new(NULL);
	rdpgfx_server_context_free(NULL);
#endif
}

/**
 * end of ugly symbols import workaround
 */
