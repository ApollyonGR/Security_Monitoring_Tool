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

int displayAnalysisMenu(SecurityEvent events[], int totalEvents){
    printf( "\n=========================="
            "\n  Security Event Summary  " 
            "\n==========================\n");
    
    printf("\nTotal Events: %d", totalEvents);
    printf("\nSuccessful Logins: 0");
    printf("\nFailed Logins: %d", countEventsByParameter(events, totalEvents, "FAILED_LOGIN"));
    printf("\nMalware Events: %d", countEventsByParameter(events, totalEvents, "MALWARE"));
    printf("\nPhishing Events: %d", countEventsByParameter(events, totalEvents, "PHISHING"));
    printf("\nPort Scan Events: %d", countEventsByParameter(events, totalEvents, "PORT_SCAN"));
    printf("\nUnauthorized Access Events: %d\n", countEventsByParameter(events, totalEvents, "UNAUTHORIZED_ACCESS"));
    
    return 0;
}

