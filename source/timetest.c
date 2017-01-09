#include <time.h>
#include <stdio.h>
#include <stdlib.h>
/*
 * test
 */
int main() {
    char *week[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    time_t timestamp;
    struct tm *p;
    time(&timestamp);
    p = localtime(&timestamp);
    printf("%d %d %d ", (1900 + p->tm_year), (1 + p->tm_mon), p->tm_mday);
    printf("%s %d:%d:%d\n", week[p->tm_wday], p->tm_hour, p->tm_min, p->tm_sec);
    printf("time = %s\n", ctime(&timestamp));
    return 0;
}
