/* Signal32 - Simple testcase for catching every possible kind of signal
   sent to this process. It is usefull for testing KFS.

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include <signal.h>
#include <stdio.h>

int wait = 1;

void signal_handler (int signum)
{
  fprintf (stderr, "signal32: signal received: %d\n", signum);

  if (signum == SIGINT)
    {
      fprintf (stderr, "Finishing...\n");
      wait = 0;
    }
}

int main ()
{
  int i;

  /* Attempt to register every type of signal to a default handler.  */
  for (i = 1; i <= 32; i++)
    {
      if (signal (i, signal_handler) == SIG_ERR)
        fprintf (stderr, "signal32: signal %d could not be registered.\n", i);
    }

  /* Wait for a signal.  */
  while (wait);

  return 0;
}

