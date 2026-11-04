#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "fileio.h"
#include "analysis.h"
#include "security_event.h"

/*
Figure out why it loops infinitely when I type a letter
Make it so choosing an option like 2 or 3 will bring you into a seperate menu, and ask you to "Press enter to return to main menu"
Figure out logic for handling menus inside of menus
*/

int MainMenu(){
    int choice;
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

int SearchMenu(){
    printf("\n==============="
           "\n  Search Menu  " 
           "\n===============\n");

    int choice;
    printf( "\n1. Search by Event Type"
            "\n2. Search by Event Source"
            "\n3. Search by Event Severity"
            "\n4. Search by Account Name"
            "\n5. Main Menu\n");

    printf("\nPlease select option: ");
    scanf("%d", &choice);
    return choice;
}

int AnalyzeMenu(){
    printf("\n================="
           "\n  Analysis Menu  " 
           "\n=================\n");
           
    int choice;
    printf( "\n1. Count Malware Incidents"
            "\n2. Count Phishing Incidents"
            "\n3. Count Port Scan Incidents"
            "\n4. Count Failed Login Incidents"
            "\n5. Count Unauthorized Access Incidents"
            "\n6. Count Total Critical Events"
            "\n7. Count Highest Severity Events"
            "\n8. Main Menu\n");

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
            case 3: 
                if (fileLoaded == true) SearchMenu();
                else printf("Error: No security log loaded\n");
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
