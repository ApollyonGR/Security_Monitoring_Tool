#include <string.h>
#include <stdio.h>
#include "helperFunctions.h"
#include "security_event.h"

int countEventsByParameter(SecurityEvent events[], int totalEvents, const char *eventType) {
    int count = 0;
    for (int i = 0; i < totalEvents; i++){
        // If the event strings are identical
        if (strcmp(events[i].eventType, eventType) == 0){
            count++;
        }
    }
    return count;
}


int countCriticalEvents(SecurityEvent events[], int totalEvents){
    int critical = 0;
    for (int i = 0; i < totalEvents; i++){
        // Counts every event with a severity greater than or equal to 9
        if (events[i].severity >= CRITICAL_THRESHOLD){
            critical++;
        }
    }
    return critical;  
}


int findHighestSeverity(SecurityEvent events[], int totalEvents){
    int highest = 0;
    for (int i = 0; i < totalEvents; i++){
        if (events[i].severity > highest){
            highest = events[i].severity;
        }
    }
    return highest;  
}

int countHighestSeverity(SecurityEvent events[], int totalEvents){
    int count = 0;
    int highest = findHighestSeverity(events, totalEvents);

    for (int i = 0; i < totalEvents; i++){
        if (events[i].severity == highest){
            count++;
        }
    }
    return count;
}

int AnalysisMenu(void){
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
    
    clearStdin();
    return choice;
}

int handleAnalysisMenu(SecurityEvent events[], int totalEvents) {
    while (1)
    {
        int analysisMenuChoice = AnalysisMenu();
        switch (analysisMenuChoice)
        {
        case 1:
            printf("\n%d matches found!\n", countEventsByParameter(events, totalEvents, "MALWARE"));
            break;

        case 2:
            printf("\n%d matches found!\n", countEventsByParameter(events, totalEvents, "PHISHING"));
            break;

        case 3:
            printf("\n%d matches found!\n", countEventsByParameter(events, totalEvents, "PORT_SCAN"));
            break;

        case 4:
            printf("\n%d matches found!\n", countEventsByParameter(events, totalEvents, "FAILED_LOGIN"));
            break;
        
        case 5:
            printf("\n%d matches found!\n", countEventsByParameter(events, totalEvents, "UNAUTHORIZED_ACCESS"));
            break;
        
        case 6:
            printf("\n%d matches found!\n", countCriticalEvents(events, totalEvents));
            break;
        
        case 7:
            printf("\n%d matches found!\n", countHighestSeverity(events, totalEvents));
            break;

        case 8:
            printf("\nExiting...\n");
            return 5;

        default:
            printf("\nError: Please enter a valid choice\n");
            break;
        }
    }
}
