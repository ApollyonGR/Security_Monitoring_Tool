#include <string.h>
#include <stdio.h>
#include "security_event.h"

int countEventsByType(SecurityEvent events[], int totalEvents, const char *eventType) {
    int count = 0;
    for (int i = 0; i < totalEvents; i++){
        // If the event strings are identical
        if (strcmp(events[i].eventType, eventType) == 0){
            count++;
        }
    }
    return count;
}

int countFailedLogins(SecurityEvent events[], int totalEvents){
    return countEventsByType(events, totalEvents, "FAILED_LOGIN");
}

int countPortScanEvents(SecurityEvent events[], int totalEvents){
    return countEventsByType(events, totalEvents, "PORT_SCAN");  
}

int countUAEvents(SecurityEvent events[], int totalEvents){
    return countEventsByType(events, totalEvents, "UNAUTHORIZED_ACCESS");  
}

int countMalwareEvents(SecurityEvent events[], int totalEvents){
    return countEventsByType(events, totalEvents, "MALWARE");  
}

int countPhishingEvents(SecurityEvent events[], int totalEvents){
    return countEventsByType(events, totalEvents, "PHISHING");  
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