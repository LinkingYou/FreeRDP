/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * X11 ENCOMSP
 *
 * Copyright 2011 Marc-Andre Moreau <marcandre.moreau@gmail.com>
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

#ifndef FREERDP_CLIENT_X11_ENCOMSP_H
#define FREERDP_CLIENT_X11_ENCOMSP_H

#if !defined(CHANNEL_ENCOMSP)
#error "CHANNEL_ENCOMSP not defined"
#endif

void xf_encomsp_init(xfContext* xfc, EncomspClientContext* encomsp);
void xf_encomsp_toggle_control(xfContext* xfc);
void xf_encomsp_uninit(xfContext* xfc, EncomspClientContext* encomsp);

#include "xf_client.h"
#include "xfreerdp.h"


#endif /* FREERDP_CLIENT_X11_ENCOMSP_H */
