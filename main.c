#include <stdio.h>
#include <stdlib.h>

#include "fileio.h"
#include "analysis.h"
#include "security_event.h"

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
    for (int c; (c = getchar()) != '\n' && c != EOF; );
    return choice;
}

int main(void){
    SecurityEvent events[MAX_EVENTS];
    int totalEvents = 0;
    int running = 1;
    bool fileLoaded = false;
    
    while(running == 1){
        int mainMenuChoice = MainMenu(); 
        switch(mainMenuChoice){
            case 1:
                totalEvents = loadEvents(LOG_RELATIVE_FILEPATH, events, MAX_EVENTS);
                if (totalEvents != -1){
                    printf("\n%d event(s) loaded!\n", totalEvents);
                    fileLoaded = true;
                }
                break;

            case 2:
                if (fileLoaded == true) displayEvents(events, totalEvents);
                else printf("\nError: No security log loaded\n");
                break;

            case 3: 
                if (fileLoaded == true) handleSearchMenuChoice(events, totalEvents);
                else {
                    printf("\nError: No security log loaded\n");
                }
                break;

            case 4: 
                if (fileLoaded == true){
                    // handleAnalyzeMenuChoice(analyzeMenuChoice, events);
                } else printf("\nError: No security log loaded\n");
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

// gcc -Wall -Wextra main.c analysis.c fileio.c security_event.c -o main && ./main  
