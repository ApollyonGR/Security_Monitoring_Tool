#include <stdio.h>
#include <string.h>
#include "security_event.h"

int loadEvents(const char *filename, SecurityEvent events[], int totalEvents){
    FILE *fptr = fopen(filename, "r");

    // If the file is empty / doesn't exist, exit gracefully
    if (fptr == NULL){
        printf("The file failed to open.\n");
        return -1;
    } 

    int i = 0; // Counter 

    // while each line has 4 whitespace-separated values
    while (i < MAX_EVENTS && fscanf(fptr, "%24s %15s %9s %d", 
                events[i].eventType, events[i].eventSource,
                events[i].accountName, &events[i].severity) == 4) {
        i++;
    }
    printf("From %s: %d event(s) loaded!\n\n",filename, i);
    fclose(fptr);
    return i; // returns the total number of events loaded for use in main.c
}

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
