/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 *
 * Copyright 2014 Marc-Andre Moreau <marcandre.moreau@gmail.com>
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

#include "shadow.h"

#include "shadow_channels.h"

#if defined(CHANNEL_REMDESK_SERVER)
#include "shadow_encomsp.h"
#endif

#if defined(CHANNEL_ENCOMSP_SERVER)
#include "shadow_remdesk.h"
#endif

#if defined(CHANNEL_RDPSND_SERVER)
#include "shadow_rdpsnd.h"
#endif

#if defined(CHANNEL_AUDIN_SERVER)
#include "shadow_audin.h"
#endif

#if defined(CHANNEL_RDPGFX_SERVER)
#include "shadow_rdpgfx.h"
#endif
UINT shadow_client_channels_post_connect(rdpShadowClient* client)
{
#if defined(CHANNEL_ENCOMSP_SERVER)

	if (WTSVirtualChannelManagerIsChannelJoined(client->vcm, ENCOMSP_SVC_CHANNEL_NAME))
		shadow_client_encomsp_init(client);

#endif
#if defined(CHANNEL_REMDESK_SERVER)

	if (WTSVirtualChannelManagerIsChannelJoined(client->vcm, REMDESK_SVC_CHANNEL_NAME))
		shadow_client_remdesk_init(client);

#endif
#if defined(CHANNEL_RDPSND_SERVER)

	if (WTSVirtualChannelManagerIsChannelJoined(client->vcm, RDPSND_SVC_CHANNEL_NAME))
		shadow_client_rdpsnd_init(client);

#endif
#if defined(CHANNEL_AUDIN_SERVER)

	if (WTSVirtualChannelManagerIsChannelJoined(client->vcm, AUDIN_SVC_CHANNEL_NAME))
		shadow_client_audin_init(client);

#endif
#if defined(CHANNEL_RDPGFX_SERVER)

	if (WTSVirtualChannelManagerIsChannelJoined(client->vcm, RDPGFX_SVC_CHANNEL_NAME))
	{
		if (client->context.settings->SupportGraphicsPipeline)
			shadow_client_rdpgfx_init(client);
	}

#endif
	return CHANNEL_RC_OK;
}

void shadow_client_channels_free(rdpShadowClient* client)
{
#if defined(CHANNEL_ENCOMSP_SERVER)
	shadow_client_encomsp_uninit(client);
#endif
#if defined(CHANNEL_REMDESK_SERVER)
	shadow_client_remdesk_uninit(client);
#endif
#if defined(CHANNEL_RDPSND_SERVER)
	shadow_client_rdpsnd_uninit(client);
#endif
#if defined(CHANNEL_AUDIN_SERVER)
	shadow_client_audin_uninit(client);
#endif
#if defined(CHANNEL_RDPGFX_SERVER)

	if (client->context.settings->SupportGraphicsPipeline)
		shadow_client_rdpgfx_uninit(client);

#endif
}
