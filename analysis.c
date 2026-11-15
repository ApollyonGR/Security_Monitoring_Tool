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

int checkFailedLogins (SecurityEvent events[], int totalEvents){
    int threshold = 5;

    // Outer loop scans for any event with a FAILED_LOGIN type
    // Once one is found, inner loop RESCANS every event, checking if any
    // other events match that events IP Address and event type.
    // Once the inner loop is finished, if the count variable is equal to
    // or above the threshold, it copies the problem address into 
    // the extern char buffer, alongisde the failed login count, and returns. 
    for (int i = 0; i < totalEvents; i++){
        if (strcmp(events[i].eventType, "FAILED_LOGIN") == 0){
            int count = 0;
            for (int j = 0; j < totalEvents; j++){
                if (strcmp(events[j].eventType, "FAILED_LOGIN") == 0 &&
                    strcmp(events[j].eventSource, events[i].eventSource) == 0){
                        count++;
                }
            }
            if (count >= threshold){
                failedLoginAlert = 1;
                strcpy(failedLoginAddress, events[i].eventSource);
                failedLoginAddressCount = count;
                return 1;
            }
        }
    }

    failedLoginAlert = 0;
    return 0;
}

int populateSecurityAlerts(SecurityEvent events[], int totalEvents){
    
    checkFailedLogins(events, totalEvents);

    if (countEventsByParameter(events, totalEvents, "MALWARE") >= 10) malwareAlert = 1;
    if (countEventsByParameter(events, totalEvents, "PHISHING") >= 10) phishingAlert = 1;
    
    // Figure out how to check if the port scan attempts cam from one address.
    if (countEventsByParameter(events, totalEvents, "PORT_SCAN") >= 10) portScanAlert = 1;

    if (countEventsByParameter(events, totalEvents, "UNAUTHORIZED_ACCESS") >= 10) UnAuthAlert = 1;

    return 0;
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

