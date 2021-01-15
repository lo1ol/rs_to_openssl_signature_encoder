/*
 * log.h: Logging functions header file
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2003  Antti Tapaninen <aet@cc.hut.fi>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _OPENSC_LOG_H
#define _OPENSC_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>

/* You can't do #ifndef __FUNCTION__ */
#if !defined(__GNUC__) && !defined(__IBMC__) && !(defined(_MSC_VER) && (_MSC_VER >= 1300))
#define __FUNCTION__ NULL
#endif

#define SC_FUNC_CALLED(ctx, level) do { \
} while (0)
#define LOG_FUNC_CALLED(ctx) SC_FUNC_CALLED((ctx), SC_LOG_DEBUG_NORMAL)

#define SC_FUNC_RETURN(ctx, level, r) do { \
	int _ret = r; \
	if (_ret <= 0) { \
	} else { \
	} \
	return _ret; \
} while(0)
#define LOG_FUNC_RETURN(ctx, r) SC_FUNC_RETURN((ctx), SC_LOG_DEBUG_NORMAL, (r))

#define SC_TEST_RET(ctx, level, r, text) do { \
	int _ret = (r); \
	if (_ret < 0) { \
		return _ret; \
	} \
} while(0)
#define LOG_TEST_RET(ctx, r, text) SC_TEST_RET((ctx), SC_LOG_DEBUG_NORMAL, (r), (text))

#define SC_TEST_GOTO_ERR(ctx, level, r, text) do { \
	int _ret = (r); \
	if (_ret < 0) { \
		goto err; \
	} \
} while(0)
#define LOG_TEST_GOTO_ERR(ctx, r, text) SC_TEST_GOTO_ERR((ctx), SC_LOG_DEBUG_NORMAL, (r), (text))

#ifdef __cplusplus
}
#endif

#endif
