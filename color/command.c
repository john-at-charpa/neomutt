/**
 * @file
 * Parse colour commands
 *
 * @authors
 * Copyright (C) 2021 Richard Russon <rich@flatcap.org>
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
 * @page color_command Parse colour commands
 *
 * Parse NeoMutt 'color', 'uncolor', 'mono' and 'unmono' commands.
 */

#include "config.h"
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "mutt/lib.h"
#include "core/lib.h"
#include "gui/lib.h"
#include "mutt.h"
#include "debug.h"
#include "init.h"
#include "options.h"

/**
 * ColorFields - Mapping of colour names to their IDs
 */
const struct Mapping ColorFields[] = {
  // clang-format off
  { "attachment",        MT_COLOR_ATTACHMENT },
  { "attach_headers",    MT_COLOR_ATTACH_HEADERS },
  { "body",              MT_COLOR_BODY },
  { "bold",              MT_COLOR_BOLD },
  { "error",             MT_COLOR_ERROR },
  { "hdrdefault",        MT_COLOR_HDRDEFAULT },
  { "header",            MT_COLOR_HEADER },
  { "index",             MT_COLOR_INDEX },
  { "index_author",      MT_COLOR_INDEX_AUTHOR },
  { "index_collapsed",   MT_COLOR_INDEX_COLLAPSED },
  { "index_date",        MT_COLOR_INDEX_DATE },
  { "index_flags",       MT_COLOR_INDEX_FLAGS },
  { "index_label",       MT_COLOR_INDEX_LABEL },
  { "index_number",      MT_COLOR_INDEX_NUMBER },
  { "index_size",        MT_COLOR_INDEX_SIZE },
  { "index_subject",     MT_COLOR_INDEX_SUBJECT },
  { "index_tag",         MT_COLOR_INDEX_TAG },
  { "index_tags",        MT_COLOR_INDEX_TAGS },
  { "indicator",         MT_COLOR_INDICATOR },
  { "markers",           MT_COLOR_MARKERS },
  { "message",           MT_COLOR_MESSAGE },
  { "normal",            MT_COLOR_NORMAL },
  { "options",           MT_COLOR_OPTIONS },
  { "progress",          MT_COLOR_PROGRESS },
  { "prompt",            MT_COLOR_PROMPT },
  { "quoted",            MT_COLOR_QUOTED },
  { "search",            MT_COLOR_SEARCH },
#ifdef USE_SIDEBAR
  { "sidebar_divider",   MT_COLOR_SIDEBAR_DIVIDER },
  { "sidebar_flagged",   MT_COLOR_SIDEBAR_FLAGGED },
  { "sidebar_highlight", MT_COLOR_SIDEBAR_HIGHLIGHT },
  { "sidebar_indicator", MT_COLOR_SIDEBAR_INDICATOR },
  { "sidebar_new",       MT_COLOR_SIDEBAR_NEW },
  { "sidebar_ordinary",  MT_COLOR_SIDEBAR_ORDINARY },
  { "sidebar_spool_file", MT_COLOR_SIDEBAR_SPOOLFILE },
  { "sidebar_spoolfile", MT_COLOR_SIDEBAR_SPOOLFILE }, // This will be deprecated
  { "sidebar_unread",    MT_COLOR_SIDEBAR_UNREAD },
#endif
  { "signature",         MT_COLOR_SIGNATURE },
  { "status",            MT_COLOR_STATUS },
  { "tilde",             MT_COLOR_TILDE },
  { "tree",              MT_COLOR_TREE },
  { "underline",         MT_COLOR_UNDERLINE },
  { "warning",           MT_COLOR_WARNING },
  { NULL, 0 },
  // clang-format on
};

/**
 * ComposeColorFields - Mapping of compose colour names to their IDs
 */
const struct Mapping ComposeColorFields[] = {
  // clang-format off
  { "header",            MT_COLOR_COMPOSE_HEADER },
  { "security_encrypt",  MT_COLOR_COMPOSE_SECURITY_ENCRYPT },
  { "security_sign",     MT_COLOR_COMPOSE_SECURITY_SIGN },
  { "security_both",     MT_COLOR_COMPOSE_SECURITY_BOTH },
  { "security_none",     MT_COLOR_COMPOSE_SECURITY_NONE },
  { NULL, 0 }
  // clang-format on
};

/**
 * parse_color_name - Parse a colour name
 * @param[in]  s     String to parse
 * @param[out] col   Number for 'colorNNN' colours
 * @param[out] attrs Attributes, e.g. A_UNDERLINE
 * @param[in]  is_fg true if this is a foreground colour
 * @param[out] err   Buffer for error messages
 * @retval #CommandResult Result e.g. #MUTT_CMD_SUCCESS
 *
 * Parse a colour name, such as "red", "brightgreen", "color123".
 */
static enum CommandResult parse_color_name(const char *s, uint32_t *col, int *attrs,
                                           bool is_fg, struct Buffer *err)
{
  char *eptr = NULL;
  bool is_alert = false, is_bright = false, is_light = false;
  int clen;

  if ((clen = mutt_istr_startswith(s, "bright")))
  {
    color_debug("bright\n");
    is_bright = true;
    s += clen;
  }
  else if ((clen = mutt_istr_startswith(s, "alert")))
  {
    color_debug("alert\n");
    is_alert = true;
    is_bright = true;
    s += clen;
  }
  else if ((clen = mutt_istr_startswith(s, "light")))
  {
    color_debug("light\n");
    is_light = true;
    s += clen;
  }

  /* allow aliases for xterm color resources */
  if ((clen = mutt_istr_startswith(s, "color")))
  {
    s += clen;
    *col = strtoul(s, &eptr, 10);
    if ((*s == '\0') || (*eptr != '\0') || ((*col >= COLORS) && !OptNoCurses))
    {
      mutt_buffer_printf(err, _("%s: color not supported by term"), s);
      return MUTT_CMD_ERROR;
    }
    color_debug("colorNNN %d\n", *col);
  }
  else if ((*col = mutt_map_get_value(s, ColorNames)) == -1)
  {
    mutt_buffer_printf(err, _("%s: no such color"), s);
    return MUTT_CMD_WARNING;
  }
  const char *name = mutt_map_get_name(*col, ColorNames);
  if (name)
    color_debug("color: %s\n", name);

  if (is_bright || is_light)
  {
    if (is_alert)
    {
      *attrs |= A_BOLD;
      *attrs |= A_BLINK;
    }
    else if (is_fg)
    {
      if ((COLORS >= 16) && is_light)
      {
        if (*col <= 7)
        {
          /* Advance the color 0-7 by 8 to get the light version */
          *col += 8;
        }
      }
      else
      {
        *attrs |= A_BOLD;
      }
    }
    else
    {
      if (COLORS >= 16)
      {
        if (*col <= 7)
        {
          /* Advance the color 0-7 by 8 to get the light version */
          *col += 8;
        }
      }
    }
  }

  return MUTT_CMD_SUCCESS;
}

/**
 * parse_attr_spec - Parse an attribute description - Implements ::parser_callback_t - @ingroup parser_callback_api
 */
static enum CommandResult parse_attr_spec(struct Buffer *buf, struct Buffer *s,
                                          uint32_t *fg, uint32_t *bg,
                                          int *attrs, struct Buffer *err)
{
  if (fg)
    *fg = COLOR_UNSET;
  if (bg)
    *bg = COLOR_UNSET;

  if (!MoreArgs(s))
  {
    mutt_buffer_printf(err, _("%s: too few arguments"), "mono");
    return MUTT_CMD_WARNING;
  }

  mutt_extract_token(buf, s, MUTT_TOKEN_NO_FLAGS);

  if (mutt_istr_equal("bold", buf->data))
    *attrs |= A_BOLD;
  else if (mutt_istr_equal("none", buf->data))
    *attrs = A_NORMAL; // Use '=' to clear other bits
  else if (mutt_istr_equal("normal", buf->data))
    *attrs = A_NORMAL; // Use '=' to clear other bits
  else if (mutt_istr_equal("reverse", buf->data))
    *attrs |= A_REVERSE;
  else if (mutt_istr_equal("standout", buf->data))
    *attrs |= A_STANDOUT;
  else if (mutt_istr_equal("underline", buf->data))
    *attrs |= A_UNDERLINE;
  else
  {
    mutt_buffer_printf(err, _("%s: no such attribute"), buf->data);
    return MUTT_CMD_WARNING;
  }

  return MUTT_CMD_SUCCESS;
}

/**
 * parse_color_pair - Parse a pair of colours - Implements ::parser_callback_t - @ingroup parser_callback_api
 *
 * Parse a pair of colours, e.g. "red default"
 */
static enum CommandResult parse_color_pair(struct Buffer *buf, struct Buffer *s,
                                           uint32_t *fg, uint32_t *bg,
                                           int *attrs, struct Buffer *err)
{
  while (true)
  {
    if (!MoreArgs(s))
    {
      mutt_buffer_printf(err, _("%s: too few arguments"), "color");
      return MUTT_CMD_WARNING;
    }

    mutt_extract_token(buf, s, MUTT_TOKEN_NO_FLAGS);

    if (mutt_istr_equal("bold", buf->data))
    {
      *attrs |= A_BOLD;
      color_debug("bold\n");
    }
    else if (mutt_istr_equal("none", buf->data))
    {
      *attrs = A_NORMAL; // Use '=' to clear other bits
      color_debug("none\n");
    }
    else if (mutt_istr_equal("normal", buf->data))
    {
      *attrs = A_NORMAL; // Use '=' to clear other bits
      color_debug("normal\n");
    }
    else if (mutt_istr_equal("reverse", buf->data))
    {
      *attrs |= A_REVERSE;
      color_debug("reverse\n");
    }
    else if (mutt_istr_equal("standout", buf->data))
    {
      *attrs |= A_STANDOUT;
      color_debug("standout\n");
    }
    else if (mutt_istr_equal("underline", buf->data))
    {
      *attrs |= A_UNDERLINE;
      color_debug("underline\n");
    }
    else
    {
      enum CommandResult rc = parse_color_name(buf->data, fg, attrs, true, err);
      if (rc != MUTT_CMD_SUCCESS)
        return rc;
      break;
    }
  }

  if (!MoreArgs(s))
  {
    mutt_buffer_printf(err, _("%s: too few arguments"), "color");
    return MUTT_CMD_WARNING;
  }

  mutt_extract_token(buf, s, MUTT_TOKEN_NO_FLAGS);

  return parse_color_name(buf->data, bg, attrs, false, err);
}

/**
 * get_colorid_name - Get the name for a color id
 * @param color Colour, e.g. #MT_COLOR_HEADER
 * @param buf   Buffer for result
 */
void get_colorid_name(unsigned int color, struct Buffer *buf)
{
  const char *name = NULL;

  if ((color >= MT_COLOR_COMPOSE_HEADER) && (color <= MT_COLOR_COMPOSE_SECURITY_SIGN))
  {
    name = mutt_map_get_name(color, ComposeColorFields);
    if (name)
    {
      mutt_buffer_printf(buf, "compose %s", name);
      return;
    }
  }

  name = mutt_map_get_name(color, ColorFields);
  if (name)
    mutt_buffer_printf(buf, "%s", name);
  else
    mutt_buffer_printf(buf, "UNKNOWN %d", color);
}

/**
 * parse_object - Identify a colour object
 * @param[in]  buf   Temporary Buffer space
 * @param[in]  s     Buffer containing string to be parsed
 * @param[out] color Object type, e.g. #MT_COLOR_TILDE
 * @param[out] ql    Quote level, if type #MT_COLOR_QUOTED
 * @param[out] err   Buffer for error messages
 * @retval #CommandResult Result e.g. #MUTT_CMD_SUCCESS
 *
 * Identify a colour object, e.g. "quoted", "compose header"
 */
static enum CommandResult parse_object(struct Buffer *buf, struct Buffer *s,
                                       enum ColorId *color, int *ql, struct Buffer *err)
{
  int rc;

  if (mutt_str_startswith(buf->data, "quoted") != 0)
  {
    int val = 0;
    if (buf->data[6] != '\0')
    {
      rc = mutt_str_atoi(buf->data + 6, &val);
      if ((rc != 0) || (val > COLOR_QUOTES_MAX))
      {
        mutt_buffer_printf(err, _("%s: no such object"), buf->data);
        return MUTT_CMD_WARNING;
      }
    }

    *ql = val;
    *color = MT_COLOR_QUOTED;
    return MUTT_CMD_SUCCESS;
  }

  if (mutt_istr_equal(buf->data, "compose"))
  {
    if (!MoreArgs(s))
    {
      mutt_buffer_printf(err, _("%s: too few arguments"), "color");
      return MUTT_CMD_WARNING;
    }

    mutt_extract_token(buf, s, MUTT_TOKEN_NO_FLAGS);

    rc = mutt_map_get_value(buf->data, ComposeColorFields);
    if (rc == -1)
    {
      mutt_buffer_printf(err, _("%s: no such object"), buf->data);
      return MUTT_CMD_WARNING;
    }

    *color = rc;
    return MUTT_CMD_SUCCESS;
  }

  rc = mutt_map_get_value(buf->data, ColorFields);
  if (rc == -1)
  {
    mutt_buffer_printf(err, _("%s: no such object"), buf->data);
    return MUTT_CMD_WARNING;
  }
  else
  {
    color_debug("object: %s\n", mutt_map_get_name(rc, ColorFields));
  }

  *color = rc;
  return MUTT_CMD_SUCCESS;
}

/**
 * parse_uncolor - Parse an 'uncolor' command
 * @param buf     Temporary Buffer space
 * @param s       Buffer containing string to be parsed
 * @param err     Buffer for error messages
 * @param uncolor If true, 'uncolor', else 'unmono'
 * @retval #CommandResult Result e.g. #MUTT_CMD_SUCCESS
 *
 * Usage:
 * * uncolor index pattern [pattern...]
 * * unmono  index pattern [pattern...]
 */
static enum CommandResult parse_uncolor(struct Buffer *buf, struct Buffer *s,
                                        struct Buffer *err, bool uncolor)
{
  mutt_extract_token(buf, s, MUTT_TOKEN_NO_FLAGS);

  if (mutt_str_equal(buf->data, "*"))
  {
    mutt_debug(LL_NOTIFY, "NT_COLOR_RESET: [ALL]\n");
    struct EventColor ev_c = { MT_COLOR_MAX, NULL };
    notify_send(ColorsNotify, NT_COLOR, NT_COLOR_RESET, &ev_c);
    colors_clear();
    return MUTT_CMD_SUCCESS;
  }

  unsigned int color = MT_COLOR_NONE;
  int ql = 0;
  color_debug("uncolor: %s\n", mutt_buffer_string(buf));
  enum CommandResult rc = parse_object(buf, s, &color, &ql, err);
  if (rc != MUTT_CMD_SUCCESS)
    return rc;

  if (color == -1)
  {
    mutt_buffer_printf(err, _("%s: no such object"), buf->data);
    return MUTT_CMD_ERROR;
  }

  if (color == MT_COLOR_QUOTED)
  {
    color_debug("quoted\n");
    return quoted_colors_parse_uncolor(color, ql, err);
  }

  if ((color == MT_COLOR_STATUS) && !MoreArgs(s))
  {
    color_debug("simple\n");
    simple_color_reset(color); // default colour for the status bar
    return MUTT_CMD_SUCCESS;
  }

  if ((color != MT_COLOR_ATTACH_HEADERS) && (color != MT_COLOR_BODY) &&
      (color != MT_COLOR_HEADER) && (color != MT_COLOR_INDEX) &&
      (color != MT_COLOR_INDEX_AUTHOR) && (color != MT_COLOR_INDEX_FLAGS) &&
      (color != MT_COLOR_INDEX_SUBJECT) && (color != MT_COLOR_INDEX_TAG) &&
      (color != MT_COLOR_STATUS))
  {
    color_debug("simple\n");
    simple_color_reset(color);
    return MUTT_CMD_SUCCESS;
  }

  if (!MoreArgs(s))
  {
    mutt_buffer_printf(err, _("%s: too few arguments"), uncolor ? "uncolor" : "unmono");
    return MUTT_CMD_WARNING;
  }

  if (OptNoCurses)
  {
    do
    {
      color_debug("do nothing\n");
      /* just eat the command, but don't do anything real about it */
      mutt_extract_token(buf, s, MUTT_TOKEN_NO_FLAGS);
    } while (MoreArgs(s));

    return MUTT_CMD_SUCCESS;
  }

  bool changes = false;
  do
  {
    mutt_extract_token(buf, s, MUTT_TOKEN_NO_FLAGS);
    if (mutt_str_equal("*", buf->data))
      return regex_colors_parse_uncolor(color, NULL, uncolor);

    changes |= regex_colors_parse_uncolor(color, buf->data, uncolor);

  } while (MoreArgs(s));

  if (changes)
  {
    get_colorid_name(color, buf);
    color_debug("NT_COLOR_RESET: %s\n", buf->data);
    struct EventColor ev_c = { color };
    notify_send(ColorsNotify, NT_COLOR, NT_COLOR_RESET, &ev_c);
    regex_colors_dump_all();
  }

  return MUTT_CMD_SUCCESS;
}

/**
 * parse_color - Parse a 'color' command
 * @param buf      Temporary Buffer space
 * @param s        Buffer containing string to be parsed
 * @param err      Buffer for error messages
 * @param callback Function to handle command - Implements ::parser_callback_t
 * @param dry_run  If true, test the command, but don't apply it
 * @param color    If true "color", else "mono"
 * @retval #CommandResult Result e.g. #MUTT_CMD_SUCCESS
 *
 * Usage:
 * * color OBJECT [ ATTRS ] FG BG [ REGEX ]
 * * mono  OBJECT   ATTRS         [ REGEX ]
 */
static enum CommandResult parse_color(struct Buffer *buf, struct Buffer *s,
                                      struct Buffer *err, parser_callback_t callback,
                                      bool dry_run, bool color)
{
  int attrs = 0, q_level = 0;
  uint32_t fg = 0, bg = 0, match = 0;
  enum ColorId object = MT_COLOR_NONE;
  enum CommandResult rc;

  if (!MoreArgs(s))
  {
    mutt_buffer_printf(err, _("%s: too few arguments"), "color");
    return MUTT_CMD_WARNING;
  }

  mutt_extract_token(buf, s, MUTT_TOKEN_NO_FLAGS);
  color_debug("color: %s\n", mutt_buffer_string(buf));

  rc = parse_object(buf, s, &object, &q_level, err);
  if (rc != MUTT_CMD_SUCCESS)
    return rc;

  rc = callback(buf, s, &fg, &bg, &attrs, err);
  if (rc != MUTT_CMD_SUCCESS)
    return rc;

  /* extract a regular expression if needed */

  if ((object == MT_COLOR_ATTACH_HEADERS) || (object == MT_COLOR_BODY) ||
      (object == MT_COLOR_HEADER) || (object == MT_COLOR_INDEX) ||
      (object == MT_COLOR_INDEX_AUTHOR) || (object == MT_COLOR_INDEX_FLAGS) ||
      (object == MT_COLOR_INDEX_SUBJECT) || (object == MT_COLOR_INDEX_TAG))
  {
    color_debug("regex needed\n");
    if (!MoreArgs(s))
    {
      mutt_buffer_printf(err, _("%s: too few arguments"), color ? "color" : "mono");
      return MUTT_CMD_WARNING;
    }

    mutt_extract_token(buf, s, MUTT_TOKEN_NO_FLAGS);
  }

  if (MoreArgs(s) && (object != MT_COLOR_STATUS))
  {
    mutt_buffer_printf(err, _("%s: too many arguments"), color ? "color" : "mono");
    return MUTT_CMD_WARNING;
  }

  if (dry_run)
  {
    color_debug("dry_run bailout\n");
    *s->dptr = '\0'; /* fake that we're done parsing */
    return MUTT_CMD_SUCCESS;
  }

#ifdef NCURSES_VERSION
  /* The case of the tree object is special, because a non-default fg color of
   * the tree element may be combined dynamically with the default bg color of
   * an index line, not necessarily defined in a rc file.  */
  if (!OptNoCurses &&
      ((fg == COLOR_DEFAULT) || (bg == COLOR_DEFAULT) || (object == MT_COLOR_TREE)) &&
      (use_default_colors() != OK))
  {
    mutt_buffer_strcpy(err, _("default colors not supported"));
    return MUTT_CMD_ERROR;
  }
#endif

  if (regex_colors_parse_color_list(object, buf->data, fg, bg, attrs, &rc, err))
  {
    color_debug("regex_colors_parse_color_list done\n");
    // do nothing
  }
  else if (quoted_colors_parse_color(object, fg, bg, attrs, q_level, &rc, err))
  {
    color_debug("quoted_colors_parse_color done\n");
    // do nothing
  }
  else if ((object == MT_COLOR_STATUS) && MoreArgs(s))
  {
    color_debug("status\n");
    /* 'color status fg bg' can have up to 2 arguments:
     * 0 arguments: sets the default status color (handled below by else part)
     * 1 argument : colorize pattern on match
     * 2 arguments: colorize nth submatch of pattern */
    mutt_extract_token(buf, s, MUTT_TOKEN_NO_FLAGS);

    if (MoreArgs(s))
    {
      struct Buffer tmp = mutt_buffer_make(0);
      mutt_extract_token(&tmp, s, MUTT_TOKEN_NO_FLAGS);
      if (mutt_str_atoui(tmp.data, &match) < 0)
      {
        mutt_buffer_printf(err, _("%s: invalid number: %s"),
                           color ? "color" : "mono", tmp.data);
        mutt_buffer_dealloc(&tmp);
        return MUTT_CMD_WARNING;
      }
      mutt_buffer_dealloc(&tmp);
    }

    if (MoreArgs(s))
    {
      mutt_buffer_printf(err, _("%s: too many arguments"), color ? "color" : "mono");
      return MUTT_CMD_WARNING;
    }

    rc = regex_colors_parse_status_list(object, buf->data, fg, bg, attrs, match, err);
  }
  else // Remaining simple colours
  {
    color_debug("simple\n");
    struct AttrColor *ac = simple_color_set(object, fg, bg, attrs);
    if (ac)
      rc = MUTT_CMD_SUCCESS;
  }

  if (rc == MUTT_CMD_SUCCESS)
  {
    get_colorid_name(object, buf);
    color_debug("NT_COLOR_SET: %s\n", buf->data);
    struct EventColor ev_c = { object };
    notify_send(ColorsNotify, NT_COLOR, NT_COLOR_SET, &ev_c);
  }

  return rc;
}

/**
 * mutt_parse_uncolor - Parse the 'uncolor' command - Implements Command::parse() - @ingroup command_parse
 */
enum CommandResult mutt_parse_uncolor(struct Buffer *buf, struct Buffer *s,
                                      intptr_t data, struct Buffer *err)
{
  if (OptNoCurses)
  {
    *s->dptr = '\0'; /* fake that we're done parsing */
    return MUTT_CMD_SUCCESS;
  }
  color_debug("parse: %s\n", mutt_buffer_string(buf));
  enum CommandResult rc = parse_uncolor(buf, s, err, true);
  // simple_colors_dump(false);
  curses_colors_dump();
  return rc;
}

/**
 * mutt_parse_unmono - Parse the 'unmono' command - Implements Command::parse() - @ingroup command_parse
 */
enum CommandResult mutt_parse_unmono(struct Buffer *buf, struct Buffer *s,
                                     intptr_t data, struct Buffer *err)
{
  if (OptNoCurses)
  {
    *s->dptr = '\0'; /* fake that we're done parsing */
    return MUTT_CMD_SUCCESS;
  }
  return parse_uncolor(buf, s, err, false);
}

/**
 * mutt_parse_color - Parse the 'color' command - Implements Command::parse() - @ingroup command_parse
 */
enum CommandResult mutt_parse_color(struct Buffer *buf, struct Buffer *s,
                                    intptr_t data, struct Buffer *err)
{
  bool dry_run = OptNoCurses;

  color_debug("parse: %s\n", mutt_buffer_string(buf));
  enum CommandResult rc = parse_color(buf, s, err, parse_color_pair, dry_run, true);
  // simple_colors_dump(false);
  curses_colors_dump();
  return rc;
}

/**
 * mutt_parse_mono - Parse the 'mono' command - Implements Command::parse() - @ingroup command_parse
 */
enum CommandResult mutt_parse_mono(struct Buffer *buf, struct Buffer *s,
                                   intptr_t data, struct Buffer *err)
{
  bool dry_run = OptNoCurses;

  return parse_color(buf, s, err, parse_attr_spec, dry_run, false);
}
