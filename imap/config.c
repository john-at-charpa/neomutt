/**
 * @file
 * Config used by libimap
 *
 * @authors
 * Copyright (C) 2020 Richard Russon <rich@flatcap.org>
 *
 * @copyright
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @page imap_config Config used by IMAP
 *
 * Config used by libimap
 */

#include "config.h"
#include <stddef.h>
#include <config/lib.h>
#include <stdbool.h>
#include <stdint.h>
#include "mutt/lib.h"
#include "conn/lib.h"
#include "auth.h"

/**
 * imap_auth_validator - Validate the "imap_authenticators" config variable - Implements ConfigDef::validator() - @ingroup cfg_def_validator
 */
static int imap_auth_validator(const struct ConfigSet *cs, const struct ConfigDef *cdef,
                               intptr_t value, struct Buffer *err)
{
  const struct Slist *imap_auth_methods = (const struct Slist *) value;
  if (!imap_auth_methods || (imap_auth_methods->count == 0))
    return CSR_SUCCESS;

  struct ListNode *np = NULL;
  STAILQ_FOREACH(np, &imap_auth_methods->head, entries)
  {
    if (imap_auth_is_valid(np->data))
      continue;
#ifdef USE_SASL
    if (sasl_auth_validator(np->data))
      continue;
#endif
    mutt_buffer_printf(err, _("Option %s: %s is not a valid authenticator"),
                       cdef->name, np->data);
    return CSR_ERR_INVALID;
  }

  return CSR_SUCCESS;
}

static struct ConfigDef ImapVars[] = {
  // clang-format off
  { "imap_check_subscribed", DT_BOOL, false, 0, NULL,
    "(imap) When opening a mailbox, ask the server for a list of subscribed folders"
  },
  { "imap_condstore", DT_BOOL, false, 0, NULL,
    "(imap) Enable the CONDSTORE extension"
  },
#ifdef USE_ZLIB
  { "imap_deflate", DT_BOOL, true, 0, NULL,
    "(imap) Compress network traffic"
  },
#endif
  { "imap_authenticators", DT_SLIST|SLIST_SEP_COLON, 0, 0, imap_auth_validator,
    "(imap) List of allowed IMAP authentication methods (colon-separated)"
  },
  { "imap_delim_chars", DT_STRING, IP "/.", 0, NULL,
    "(imap) Characters that denote separators in IMAP folders"
  },
  { "imap_fetch_chunk_size", DT_LONG|DT_NOT_NEGATIVE, 0, 0, NULL,
    "(imap) Download headers in blocks of this size"
  },
  { "imap_headers", DT_STRING|R_INDEX, 0, 0, NULL,
    "(imap) Additional email headers to download when getting index"
  },
  { "imap_idle", DT_BOOL, false, 0, NULL,
    "(imap) Use the IMAP IDLE extension to check for new mail"
  },
  { "imap_login", DT_STRING|DT_SENSITIVE, 0, 0, NULL,
    "(imap) Login name for the IMAP server (defaults to `$imap_user`)"
  },
  { "imap_oauth_refresh_command", DT_STRING|DT_COMMAND|DT_SENSITIVE, 0, 0, NULL,
    "(imap) External command to generate OAUTH refresh token"
  },
  { "imap_pass", DT_STRING|DT_SENSITIVE, 0, 0, NULL,
    "(imap) Password for the IMAP server"
  },
  { "imap_pipeline_depth", DT_NUMBER|DT_NOT_NEGATIVE, 15, 0, NULL,
    "(imap) Number of IMAP commands that may be queued up"
  },
  { "imap_rfc5161", DT_BOOL, true, 0, NULL,
    "(imap) Use the IMAP ENABLE extension to select capabilities"
  },
  { "imap_server_noise", DT_BOOL, true, 0, NULL,
    "(imap) Display server warnings as error messages"
  },
  { "imap_keepalive", DT_NUMBER|DT_NOT_NEGATIVE, 300, 0, NULL,
    "(imap) Time to wait before polling an open IMAP connection"
  },
  { "imap_list_subscribed", DT_BOOL, false, 0, NULL,
    "(imap) When browsing a mailbox, only display subscribed folders"
  },
  { "imap_passive", DT_BOOL, true, 0, NULL,
    "(imap) Reuse an existing IMAP connection to check for new mail"
  },
  { "imap_peek", DT_BOOL, true, 0, NULL,
    "(imap) Don't mark messages as read when fetching them from the server"
  },
  { "imap_poll_timeout", DT_NUMBER|DT_NOT_NEGATIVE, 15, 0, NULL,
    "(imap) Maximum time to wait for a server response"
  },
  { "imap_qresync", DT_BOOL, false, 0, NULL,
    "(imap) Enable the QRESYNC extension"
  },
  { "imap_user", DT_STRING|DT_SENSITIVE, 0, 0, NULL,
    "(imap) Username for the IMAP server"
  },

  { "imap_servernoise", DT_SYNONYM, IP "imap_server_noise", },

  { NULL },
  // clang-format on
};

/**
 * config_init_imap - Register imap config variables - Implements ::module_init_config_t - @ingroup cfg_module_api
 */
bool config_init_imap(struct ConfigSet *cs)
{
  return cs_register_variables(cs, ImapVars, 0);
}
