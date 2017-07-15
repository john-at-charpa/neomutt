/**
 * Copyright (C) 1999-2002 Thomas Roessler <roessler@does-not-exist.org>
 *
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

/* simple, editor-based message editing */

#include "config.h"
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "mutt.h"
#include "context.h"
#include "copy.h"
#include "globals.h"
#include "header.h"
#include "lib.h"
#include "mailbox.h"
#include "mx.h"
#include "options.h"
#include "protos.h"

/**
 * edit_one_message - Edit an email
 * @param ctx Context
 * @param cur Header of email
 * @return
 * * 1  Message not modified
 * * 0  Message edited successfully
 * * -1 Error
 */
static int edit_one_message(struct Context *ctx, struct Header *cur)
{
  char tmp[_POSIX_PATH_MAX];
  char buff[STRING];
  int omagic;
  int oerrno;
  int rc;

  bool o_read;
  bool o_old;

  int of, cf;

  struct Context tmpctx;
  struct Message *msg = NULL;

  FILE *fp = NULL;

  struct stat sb;
  time_t mtime = 0;

  mutt_mktemp(tmp, sizeof(tmp));

  omagic = DefaultMagic;
  DefaultMagic = MUTT_MBOX;

  rc = (mx_open_mailbox(tmp, MUTT_NEWFOLDER, &tmpctx) == NULL) ? -1 : 0;

  DefaultMagic = omagic;

  if (rc == -1)
  {
    mutt_error(_("could not create temporary folder: %s"), strerror(errno));
    return -1;
  }

  rc = mutt_append_message(
      &tmpctx, ctx, cur, 0,
      CH_NOLEN | ((ctx->magic == MUTT_MBOX || ctx->magic == MUTT_MMDF) ? 0 : CH_NOSTATUS));
  oerrno = errno;

  mx_close_mailbox(&tmpctx, NULL);

  if (rc == -1)
  {
    mutt_error(_("could not write temporary mail folder: %s"), strerror(oerrno));
    goto bail;
  }

  if ((rc = stat(tmp, &sb)) == -1)
  {
    mutt_error(_("Can't stat %s: %s"), tmp, strerror(errno));
    goto bail;
  }

  /*
   * 2002-09-05 me@sigpipe.org
   * The file the user is going to edit is not a real mbox, so we need to
   * truncate the last newline in the temp file, which is logically part of
   * the message separator, and not the body of the message.  If we fail to
   * remove it, the message will grow by one line each time the user edits
   * the message.
   */
  if (sb.st_size != 0 && truncate(tmp, sb.st_size - 1) == -1)
  {
    mutt_error(_("could not truncate temporary mail folder: %s"), strerror(errno));
    goto bail;
  }

  mtime = mutt_decrease_mtime(tmp, &sb);

  mutt_edit_file(NONULL(Editor), tmp);

  if ((rc = stat(tmp, &sb)) == -1)
  {
    mutt_error(_("Can't stat %s: %s"), tmp, strerror(errno));
    goto bail;
  }

  if (sb.st_size == 0)
  {
    mutt_message(_("Message file is empty!"));
    rc = 1;
    goto bail;
  }

  if (sb.st_mtime == mtime)
  {
    mutt_message(_("Message not modified!"));
    rc = 1;
    goto bail;
  }

  if ((fp = fopen(tmp, "r")) == NULL)
  {
    rc = -1;
    mutt_error(_("Can't open message file: %s"), strerror(errno));
    goto bail;
  }

  if (mx_open_mailbox(ctx->path, MUTT_APPEND, &tmpctx) == NULL)
  {
    rc = -1;
    /* L10N: %s is from strerror(errno) */
    mutt_error(_("Can't append to folder: %s"), strerror(errno));
    goto bail;
  }

  of = 0;
  cf = ((tmpctx.magic == MUTT_MBOX || tmpctx.magic == MUTT_MMDF) ? 0 : CH_NOSTATUS);

  if (fgets(buff, sizeof(buff), fp) && is_from(buff, NULL, 0, NULL))
  {
    if (tmpctx.magic == MUTT_MBOX || tmpctx.magic == MUTT_MMDF)
      cf = CH_FROM | CH_FORCE_FROM;
  }
  else
    of = MUTT_ADD_FROM;

  /*
   * XXX - we have to play games with the message flags to avoid
   * problematic behavior with maildir folders.
   *
   */

  o_read = cur->read;
  o_old = cur->old;
  cur->read = cur->old = false;
  msg = mx_open_new_message(&tmpctx, cur, of);
  cur->read = o_read;
  cur->old = o_old;

  if (!msg)
  {
    mutt_error(_("Can't append to folder: %s"), strerror(errno));
    mx_close_mailbox(&tmpctx, NULL);
    goto bail;
  }

  if ((rc = mutt_copy_hdr(fp, msg->fp, 0, sb.st_size, CH_NOLEN | cf, NULL)) == 0)
  {
    fputc('\n', msg->fp);
    mutt_copy_stream(fp, msg->fp);
  }

  rc = mx_commit_message(msg, &tmpctx);
  mx_close_message(&tmpctx, &msg);

  mx_close_mailbox(&tmpctx, NULL);

bail:
  if (fp)
    safe_fclose(&fp);

  if (rc >= 0)
    unlink(tmp);

  if (rc == 0)
  {
    mutt_set_flag(Context, cur, MUTT_DELETE, 1);
    mutt_set_flag(Context, cur, MUTT_PURGE, 1);
    mutt_set_flag(Context, cur, MUTT_READ, 1);

    if (option(OPTDELETEUNTAG))
      mutt_set_flag(Context, cur, MUTT_TAG, 0);
  }
  else if (rc == -1)
    mutt_message(_("Error. Preserving temporary file: %s"), tmp);


  return rc;
}

int mutt_edit_message(struct Context *ctx, struct Header *hdr)
{
  int j;

  if (hdr)
    return edit_one_message(ctx, hdr);


  for (int i = 0; i < ctx->vcount; i++)
  {
    j = ctx->v2r[i];
    if (ctx->hdrs[j]->tagged)
    {
      if (edit_one_message(ctx, ctx->hdrs[j]) == -1)
        return -1;
    }
  }

  return 0;
}
