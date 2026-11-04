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

int MainMenu(){
    int choice;

    printf( "\n1. Load Security Log"
            "\n2. Display All Events"
            "\n3. Search Events"
            "\n4. Analyze Security Events"
            "\n5. Display Security Alerts"
            "\n6. Generate Security Report"
            "\n7. Exit\n");

    printf("\nPlease select option: ");
    scanf("%d", &choice);

    return choice;
}

int main(void){
    SecurityEvent events[MAX_EVENTS];
    int totalEvents = 0;
    bool running = true;
    bool fileLoaded = false;
    int mainMenuChoice = 0;
    
    printf("=====================================\n"
           "  CYBR 310 Security Monitoring Tool  \n" 
           "=====================================\n");

    while(running == true){
        mainMenuChoice = MainMenu(); 
        switch(mainMenuChoice){
            case 1:
                totalEvents = loadEvents(LOG_RELATIVE_FILEPATH, events, MAX_EVENTS);
                if (totalEvents != -1){
                    printf("%d event(s) loaded!\n", totalEvents);
                    fileLoaded = true;
                }
                break;
            case 2:
                if (fileLoaded == true) displayEvents(events, MAX_EVENTS);
                else printf("Error: No security log loaded\n");
                break;
            case 7:
                printf("\nExiting...\n");
                running = false;
        }
    }
    return 0;
}

// gcc -Wall -Wextra main.c analysis.c fileio.c security_event.c -o main && ./main  


//     case 3:
//         printf("\nYou picked option 3\n");
//         return 3;
//     case 4:
//         printf("\nYou picked option 4\n");
//         return 4;
//     case 5:
//         printf("\nYou picked option 5\n");
//         return 5;
//     case 6: 
//         printf("\nYou picked option 6\n");
//         return 6;
//     case 7:
//         printf("\nExiting...\n");
//         return 0;
//     default:
//         printf("\nErr: not valid option\n\n");
//         break;
// }