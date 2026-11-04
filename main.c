#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "fileio.h"
#include "analysis.h"
#include "security_event.h"

/*
Figure out why it loops infinitely when I type a letter
Make it so choosing an option like 2 or 3 will bring you into a seperate menu, and ask you to "Press enter to return to main menu"
*/

int MainMenu(SecurityEvent events[], int totalEvents){
    int choice;
    static bool fileLoaded = false;

    printf("\n"
        "=====================================\n"
        "  CYBR 310 Security Monitoring Tool  \n" 
        "=====================================\n"
        "\n"                                   );

    while(1){
        printf( "1. Load Security Log\n"
                "2. Display All Events\n"
                "3. Search Events\n"
                "4. Analyze Security Events\n"
                "5. Display Security Alerts\n"
                "6. Generate Security Report\n"
                "7. Exit\n");
        printf("\nPlease select option: ");
        scanf("%d", &choice);
        switch(choice) {
            case 1:
                // Ensures loadEvents completes successfully so displayEvents doesn't read from random memory if a bad filename is given.
                if (loadEvents(LOG_RELATIVE_FILEPATH, events, MAX_EVENTS) != -1){
                    printf("%d event(s) loaded!\n\n", totalEvents);
                    fileLoaded = true;
                }
                break;
            case 2:
                if (fileLoaded == true) displayEvents(events, MAX_EVENTS);
                else printf("\nError: No security log loaded\n\n");
                break;
            case 3:
                printf("\nYou picked option 3\n");
                return 3;
            case 4:
                printf("\nYou picked option 4\n");
                return 4;
            case 5:
                printf("\nYou picked option 5\n");
                return 5;
            case 6: 
                printf("\nYou picked option 6\n");
                return 6;
            case 7:
                printf("\nExiting...\n");
                return 0;
            default:
                printf("\nErr: not valid option\n\n");
                break;
        }
    }
}

int main(void){
    SecurityEvent events[MAX_EVENTS];
    int totalEvents = loadEvents(LOG_RELATIVE_FILEPATH, events, MAX_EVENTS);
    
    MainMenu(events, totalEvents);
    return 0;
}

// gcc -Wall -Wextra main.c analysis.c fileio.c security_event.c -o main && ./main  