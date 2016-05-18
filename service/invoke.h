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
 * \defgroup service-invoke Invoke service
 * \ingroup services
 *
 * @brief Service handling invocation of other services
 *
 * The invoke service is a special service that is required to
 * cause servers to invoke services by other services. Assume
 * Alice wants to connect her trusted work station located at
 * home with a display located at work. She will start up the
 * controller application on her mobile phone and now has to
 * somehow tell her work station to connect to the display.
 *
 * Exactly this functionality is provided by the invoke service.
 * She will initially create a new session on the display service
 * with her work station's identity specified as the invoker. She
 * now tells the invoker service on her work station to connect
 * to the display given the session she has just created. The
 * invoke service will now start the session with the display
 * service.
 */

struct sd_service;

int sd_invoke_init_service(struct sd_service *service);