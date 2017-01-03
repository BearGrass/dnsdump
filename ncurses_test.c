#include <stdio.h>
#include <ncurses.h>

/* http://www.tldp.org/HOWTO/NCURSES-Programming-HOWTO/ */

int main(void) {
    /* compile with gcc -lncurses file.c */
    int c = 0;
    /* Init ncurses mode */
    initscr();
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
