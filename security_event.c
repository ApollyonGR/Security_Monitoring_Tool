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

void displayEvents(SecurityEvent events[], int totalEvents) {
    // Defining column headers
    const char* h1 = "ID";
    const char* h2 = "EVENT TYPE";
    const char* h3 = "IP ADDRESS";
    const char* h4 = "USERNAME";
    const char* h5 = "SEVERITY";

    // Defining column widths
    int w1 = 6; 
    int w2 = 24; 
    int w3 = 20; 
    int w4 = 14; 

    // Printing the header
    printf("\n%-*s%-*s%-*s%-*s%s\n", 
           w1, h1, w2, h2, w3, h3, w4, h4, h5);
    
    // Printing a dashed line who's size changes dynamically 
    int totalWidth = w1 + w2 + w3 + w4 + (int)strlen(h5);
    for (int i = 0; i < totalWidth; i++) printf("-");
    printf("\n");

    // Printing rows 
    for (int i = 0; i < totalEvents; i++) {
        printf("%-*d%-*s%-*s%-*s%d\n", 
               w1, i + 1, 
               w2, events[i].eventType, 
               w3, events[i].eventSource, 
               w4, events[i].accountName, 
               events[i].severity);
    }
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

    // removes first \n before fgets
    for (int c; (c = getchar()) != '\n' && c != EOF; );

    return choice;
}

// shorthand for Print and Prompt, a helper function that handles user input and it's validation
int pnp (const char *prompt, char *dest, size_t size) {
    printf("\n%s", prompt);
    fgets(dest, size, stdin);
    dest[strcspn(dest, "\n")] = '\0'; // replaces second \n with \0 after fgets

    return strcmp(dest, "q") != 0; // returns one if it's a search term, or 0 if it's q
}

int handleSearchMenuChoice(int searchMenuChoice, SecurityEvent events[]){
    char target[MAX_EVENT_LENGTH];
    while(1){
        switch(searchMenuChoice){
            case 1:
                if (!pnp("\nPlease enter the event type you'd like to search, or type q to return: ", target, sizeof(target)))
                    return -1; // if the pnp function failed, exit gracefully.
                
                printf("\n");
                searchByEventType(events, MAX_EVENTS, target);
                break;
            case 2:
                if (!pnp("\nPlease enter the IP address you'd like to search, or type q to return: ", target, sizeof(target)))
                    return -1;
                
                printf("\n");
                // searchByEventAddress(events, MAX_EVENTS, target);
                return 0;
            case 3:
                if (!pnp("\nPlease enter the severity level you'd like to search, or type q to return: ", target, sizeof(target)))
                    return -1;
                
                printf("\n");
                // searchByEventSeverity(events, MAX_EVENTS, target);
                return 0;
            case 4:
                if (!pnp("\nPlease enter the account name you'd like to search, or type q to return: ", target, sizeof(target)))
                    return -1;
                
                printf("\n");
                // searchByAccountName(events, MAX_EVENTS, target);
                return 0;
            case 5:
                printf("\nExiting...\n");
                return 5;
            default:
                printf("\nError: Please enter a valid choice\n");
                break;
        }
    }
}

int searchByEventType(SecurityEvent events[], int count, char target[]){
    int matches = 0;

    if (target == NULL){
        printf("\nError: Invalid event type\n");
        return -1;
    }

    for (int i = 0; i < count; i++){
        if (strcmp(events[i].eventType, target) == 0){
            matches++;
            printf("Event %d: %s, %s, %s\n", 
                i, target, events[i].eventSource, events[i].accountName);
        }
    }
    if (matches == 0){
        printf("Match not found, no matching events present or invalid event type\n");
    }
    return matches;
}