/*
 * Copyright (C) 2016 Patrick Steinhardt
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * \defgroup service-capabilities Capabilities service
 * \ingroup services
 *
 * @brief Service handling capabilities
 *
 * The capability service is able to relay capabilities between
 * two identities. Given an entity registering at a capability
 * service, he will now receive capability requests from other
 * entities.
 *
 * Take as an example two parties Alice and Bob, where Bob
 * registered his mobile phone with a capability service. He now
 * has a connection that is kept available until he wishes to
 * de-register.
 *
 * Now Alice wants to ask Bob wether she is allowed to connect to
 * a display that Bob owns. She will submit a request to the
 * capability service in which she states that she wants to
 * connect to the display with a set of parameters. Bob will now
 * receive a request on his mobile phone, asking him wether this
 * specific request is allowed. When he accepts the request,
 * Bob's mobile phone will establish a new session with the
 * display service with Alice as the invoker and her parameters.
 * He then passes the newly created capability back to the
 * capability service which forwards it to Alice.
 *
 * Now Alice can connect to the service and use the display.
 */

struct cpn_service;

int cpn_capabilities_init_service(struct cpn_service *service);
