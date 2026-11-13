/* check_exec.c - ask the kernel whether a file may be executed, and whether
   the result needs to be enforced (Linux AT_EXECVE_CHECK and securebits). */

/* Copyright (C) 2026 Free Software Foundation, Inc.

   This file is part of GNU Bash, the Bourne Again SHell.

   Bash is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   Bash is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with Bash.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <config.h>

#if defined (EXEC_CHECK)

#include <bashtypes.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <errno.h>
#include <fcntl.h>

#if defined (__linux__)
#  include <sys/prctl.h>
#  include <sys/syscall.h>
#endif

#include <bashintl.h>
#include <shell.h>

#if !defined (errno)
extern int errno;
#endif

#if defined (__linux__) && defined (SYS_execveat) && defined (PR_GET_SECUREBITS)

/* From <linux/fcntl.h> and <linux/securebits.h>, new in Linux 6.14. */
#if !defined (AT_EMPTY_PATH)
#  define AT_EMPTY_PATH 0x1000
#endif
#if !defined (AT_EXECVE_CHECK)
#  define AT_EXECVE_CHECK 0x10000
#endif
#if !defined (SECBIT_EXEC_RESTRICT_FILE)
#  define SECBIT_EXEC_RESTRICT_FILE	(1 << 8)
#endif
#if !defined (SECBIT_EXEC_DENY_INTERACTIVE)
#  define SECBIT_EXEC_DENY_INTERACTIVE	(1 << 10)
#endif

/* Ask the kernel whether it would allow the file open on FD to be executed.
   This takes file permissions, noexec mounts, and LSM policy into account.
   NAME is the name FD was opened with; it's passed as argv[0] so the check
   can be audited.  Returns 0 if execution is allowed, -1 with errno set if
   it is not (or if the kernel doesn't support the check). */
static int
check_exec (int fd, const char *name)
{
  char *argv[2];

  argv[0] = (char *)(name ? name : "");
  argv[1] = (char *)NULL;

  return (syscall (SYS_execveat, fd, "", argv, (char **)NULL,
		   AT_EMPTY_PATH | AT_EXECVE_CHECK) == 0 ? 0 : -1);
}

/* Return non-zero if securebit BIT is set for this process.  Preserves
   errno. */
static int
securebit_set (int bit)
{
  int secbits, e;

  e = errno;
  secbits = prctl (PR_GET_SECUREBITS);
  errno = e;

  return (secbits > 0 && (secbits & bit) != 0);
}

#else /* !__linux__ || !SYS_execveat || !PR_GET_SECUREBITS */

#  define check_exec(fd, name)	(0)
#  define securebit_set(bit)	(0)

#endif /* !__linux__ || !SYS_execveat || !PR_GET_SECUREBITS */

/* This implements the policy from Documentation/userspace-api/check_exec.rst
   in the Linux sources: always ask the kernel whether a file may be executed
   before reading commands from it, so the access can be audited, but only
   act on the answer if the process has the corresponding securebit set. */

/* Return non-zero if the shell must not run commands that don't come from a
   file the kernel would allow to be executed (SECBIT_EXEC_DENY_INTERACTIVE):
   command strings, commands the user types, and code taken from the
   environment. */
int
exec_deny_interactive (void)
{
  return (securebit_set (SECBIT_EXEC_DENY_INTERACTIVE));
}

/* The shell is about to read commands from the file NAME open on FD.  If
   INTERACTIVE is non-zero, the file holds commands the user typed (fc), so
   it's subject to SECBIT_EXEC_DENY_INTERACTIVE instead of
   SECBIT_EXEC_RESTRICT_FILE.
   Returns FD if that's allowed.  If it's not, closes FD and returns -1 with
   errno set, as if the file could not be opened.  A negative FD is returned
   unchanged, so this can be called right after open(). */
int
exec_check_file (int fd, const char *name, int interactive)
{
  int e;

  if (fd < 0 || check_exec (fd, name) == 0)
    return fd;

  if (securebit_set (interactive ? SECBIT_EXEC_DENY_INTERACTIVE
				 : SECBIT_EXEC_RESTRICT_FILE) == 0)
    return fd;

  e = errno;
  close (fd);
  errno = e;
  return -1;
}

/* The shell is about to read commands from somewhere other than a script
   file: a command string if COMMAND_STRING is non-zero (-c), the standard
   input otherwise.  A command string is always interactive input; the
   standard input is acceptable if it's a file the kernel would allow to be
   executed (bash < script).
   Returns 0 if that's allowed.  If it's not, prints an error message and
   returns -1. */
int
exec_check_commands (int command_string)
{
  if (command_string == 0 && check_exec (0, "/dev/stdin") == 0)
    return 0;

  if (exec_deny_interactive () == 0)
    return 0;

  internal_error (_("%s: cannot execute: interactive commands are not allowed"),
		  command_string ? "-c" : _("standard input"));
  return -1;
}

#endif /* EXEC_CHECK */
