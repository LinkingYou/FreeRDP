/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * FreeRDP Sample Server (Audio Input)
 *
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

#ifndef FREERDP_SERVER_SAMPLE_SF_AUDIN_H
#define FREERDP_SERVER_SAMPLE_SF_AUDIN_H

#if !defined(CHANNEL_AUDIN) || !defined(CHANNEL_AUDIN_SERVER)
#error "CHANNEL_AUDIN or CHANNEL_AUDIN_SERVER not defined!"
#endif

#include <winpr/wtypes.h>

#include "sfreerdp.h"

BOOL sf_peer_audin_init(testPeerContext* context);
BOOL sf_peer_audin_toggle(testPeerContext* context);
void sf_peer_audin_uninit(testPeerContext* context);

#endif /* FREERDP_SERVER_SAMPLE_SF_AUDIN_H */

