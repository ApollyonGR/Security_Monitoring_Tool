#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "fileio.h"
#include "analysis.h"
#include "security_event.h"

/*
Figure out why it loops infinitely when I type a letter
Figure out logic for handling menus inside of menus
Add search functionality
*/

int MainMenu(){
    int choice;
    
    printf("=====================================\n"
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
    return choice;
}

int main(void){
    SecurityEvent events[MAX_EVENTS];
    int totalEvents = 0;
    bool running = true;
    bool fileLoaded = false;
    
    while(running == true){
        int mainMenuChoice = MainMenu(); 
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
            case 3: 
                if (fileLoaded == true){
                    int searchMenuChoice = SearchMenu();
                    handleSearchMenuChoice(searchMenuChoice, events);
                } else {
                    printf("Error: No security log loaded\n");
                }
                break;
            case 4: 
                if (fileLoaded == true) AnalyzeMenu();
                else printf("Error: No security log loaded\n");
                break;
            case 7:
                printf("\nExiting...\n");
                running = false;
                break;
            default:
                printf("\nError: not valid option\n\n");
                break;
        }
    }
    return 0;
}

// gcc -Wall -Wextra main.c analysis.c fileio.c security_event.c -o main && ./main  
