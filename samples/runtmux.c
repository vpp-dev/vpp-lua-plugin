#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>



int main(int argc, char *argv[]) {
  int tty = open("/dev/tty", O_RDWR);
  char *tmux = getenv("REAL_TMUX");
  int i;
  if (!tmux) {
    fprintf(stderr, "error: REAL_TMUX environment variable needs to point to real tmux\n");
    exit(1);
  }
  for(i=0; i<3; i++) {
    close(i);
    dup2(tty, i);
  }
  close(tty);
  argv[0] = tmux;
  execv(tmux, argv);
  exit(0);
}
