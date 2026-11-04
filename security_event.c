#include <stdio.h>
#include <string.h>
#include "security_event.h"

// Expects pre-validated input, run loadEvents() first.
void displayEvent(int i, SecurityEvent events[]){
    i -= 1; // Lowers number provided by one to account for 0th index
    printf("%d. %s\n"
                "   IP Address: %s\n"
                "   Username: %s\n"
                "   Severity: %d\n\n", 
            i+1, events[i].eventType, events[i].eventSource,
            events[i].accountName, events[i].severity);
}

void displayEvents(SecurityEvent events[], int totalEvents){
    for (int i = 0; i < totalEvents; i++){
        printf("%d. %s\n"
                    "   IP Address: %s\n"
                    "   Username: %s\n"
                    "   Severity: %d\n\n", 
                i+1, events[i].eventType, events[i].eventSource,
                events[i].accountName, events[i].severity);
    }
}
