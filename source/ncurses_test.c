#include <stdio.h>
#include <ncurses.h>

/* http://www.tldp.org/HOWTO/NCURSES-Programming-HOWTO/ */

WINDOW *wind;
int main(void) {
    /* compile with gcc -lncurses file.c */
    int c = 0;
    char a;
    /* Init ncurses mode */
    wind = initscr();
    cbreak();
    noecho();
    nodelay(wind, 1);
    /* Hide cursor */
    curs_set(0);
    while (c < 1000) {
        /* Print at row 0, col 0 */
        mvprintw(0, 0, "%d", c++);
        refresh();
        sleep(1);
    }
    /* End ncurses mode */
    endwin();
    return 0;
}
