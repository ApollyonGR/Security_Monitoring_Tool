#include <stdio.h>
#include <stdlib.h>

#include "fileio.h"
#include "analysis.h"
#include "security_event.h"
#include "helperFunctions.h"

/*
TO-DO: 
    1) Add analyze menu
    2) Add security alerts 
    3) Add security report generation
*/

int MainMenu(){
    int choice;
    
    printf("\n=====================================\n"
             "  CYBR 310 Security Monitoring Tool  \n" 
             "=====================================\n");

    printf( "\n1. Load Security Log"
            "\n2. Display All Events"
            "\n3. Search Events"
            "\n4. Analyze Security Events"
            "\n5. Display Security Alerts"
            "\n6. Generate Security Report"
            "\n7. Exit...\n");

    printf("\nPlease select option: ");
    scanf("%d", &choice);
    clearStdin();
    return choice;
}

int main(void){
    SecurityEvent events[MAX_EVENTS];
    int totalEvents = 0;
    int running = 1;
    int fileLoaded = 0;
    
    while(running == 1){
        int mainMenuChoice = MainMenu(); 
        switch(mainMenuChoice){
            case 1:
                totalEvents = loadEvents(LOG_RELATIVE_FILEPATH, events, MAX_EVENTS);
                if (totalEvents != -1){
                    printf("\n%d event(s) loaded!\n", totalEvents);
                    fileLoaded = 1;
                }
                break;

            case 2:
                if (fileLoaded == 1) displayEvents(events, totalEvents);
                else printf("\nError: No security log loaded\n");
                break;

            case 3: 
                if (fileLoaded == 1) handleSearchMenu(events, totalEvents);
                else {
                    printf("\nError: No security log loaded\n");
                }
                break;

            case 4: 
                if (fileLoaded == 1) handleAnalysisMenu(events, totalEvents);
                else {
                    printf("\nError: No security log loaded\n");
                }
                break;

            case 7:
                printf("\nExiting...\n");
                running = 0;
                break;

            default:
                printf("\nError: not valid option\n");
                break;
        }
    }
    return 0;
}
