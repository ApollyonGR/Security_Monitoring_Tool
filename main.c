#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

#include "fileio.h"
#include "analysis.h"
#include "security_event.h"
#include "helperFunctions.h"

/*
TO-DO: 
    1) Add security alerts for 
        a) Failed Login (DONE)
        b) Malware
        c) Phishing(?)
        d) Port Scan (DONE)
        e) Unauthorized Access 
    2) Flesh out security report generation
    3) Add functionality for custom log files
        a) Function to display available log files
        b) change the "Load Security Log" case to accept a log name
        c) change loadEvents to use that logname and return -1 if it doesn't exist
*/
int logMenu(){
    struct dirent *de;  
    DIR *dr = opendir("./logs/");

    if (dr == NULL){
        printf("Could not open current directory" );
        return -1; }

    printf("\n");
    while ((de = readdir(dr)) != NULL){
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0){
            continue;
        }
        printf("%s\n", de->d_name);
    }

    closedir(dr);
    return 0;
}

int MainMenu(){
    int choice;
    
    printf("\n=====================================\n"
             "  CYBR 310 Security Monitoring Tool  \n" 
             "=====================================\n");

    printf( "\n1. Display Available Logs"
            "\n2. Load Security Log"
            "\n3. Display All Events"
            "\n4. Search Events"
            "\n5. Analyze Security Events"
            "\n6. Display Security Alerts"
            "\n7. Generate Security Report"
            "\n8. Exit...\n");

    printf("\nPlease select option: ");
    scanf("%d", &choice);
    clearStdin();
    return choice;
}

int main(void){
    SecurityEvent *events = NULL;
    int totalEvents = 0;
    int capacity = 0;
    int running = 1;
    int fileLoaded = 0;
    
    while(running == 1){
        int mainMenuChoice = MainMenu(); 
        switch(mainMenuChoice){
            case 1:
                logMenu();
                break;

            case 2:
                totalEvents = loadEvents(LOG_RELATIVE_FILEPATH, &events, &capacity);
                if (totalEvents != -1){
                    printf("\n%d event(s) loaded!\n", totalEvents);
                    fileLoaded = 1;
                } else {
                    printf("\nError loading log file: no logs present or file does not exist\n");
                }
                break;

            case 3:
                if (fileLoaded == 1) displayEvents(stdout, events, totalEvents);
                else printf("\nError: No security log loaded\n");
                break;

            case 4: 
                if (fileLoaded == 1) handleSearchMenu(events, totalEvents);
                else {
                    printf("\nError: No security log loaded\n");
                }
                break;

            case 5: 
                if (fileLoaded == 1) displayAnalysisMenu(events, totalEvents);
                else {
                    printf("\nError: No security log loaded\n");
                }
                break;

            case 6:
                if (fileLoaded == 1){
                    populateSecurityAlerts(events, totalEvents);
                    displaySecurityAlerts();
                } else {
                    printf("\nError: No security log loaded\n");
                }
                break;
            
            case 7:
                if (fileLoaded == 1){
                    generateReport("report.txt", events, totalEvents);
                } else {
                    printf("\nError: No security log loaded\n");
                }
                break;
                
            case 8:
                printf("\nExiting...\n");
                free(events);
                events = NULL;
                running = 0;
                break;

            default:
                printf("\nError: not valid option\n");
                break;
        }
    }
    return 0;
}
