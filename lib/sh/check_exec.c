/* check_exec.c - check whether the kernel permits execution of a script */

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

#ifdef __linux__
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#ifndef AT_EMPTY_PATH
#  define AT_EMPTY_PATH 0x1000
#endif
#ifndef AT_EXECVE_CHECK
#  define AT_EXECVE_CHECK 0x10000
#endif
#ifndef SECBIT_EXEC_RESTRICT_FILE
#  define SECBIT_EXEC_RESTRICT_FILE (1 << 8)
#endif

/*
 * Check whether the kernel permits execution of the file referenced by fd.
 * Returns -1 (errno set by the kernel) if execution is denied and
 * SECBIT_EXEC_RESTRICT_FILE is set, 0 otherwise.
 * See Documentation/userspace-api/check_exec.rst.
 */
int
check_exec (int fd)
{
  static char *argv[] = { "", NULL };
  static char *envp[] = { NULL };
  int secbits;

  if (syscall (SYS_execveat, fd, "", argv, envp,
               AT_EMPTY_PATH | AT_EXECVE_CHECK) == 0)
    return 0;

  /* Kernel too old or flag unknown */
  if (errno == ENOSYS || errno == EINVAL)
    return 0;

  secbits = prctl (PR_GET_SECUREBITS);
  return ((secbits > 0 && (secbits & SECBIT_EXEC_RESTRICT_FILE)) ? -1 : 0);
}

#else /* !__linux__ */

int
check_exec (int fd)
{
  return 0;
}

#endif
