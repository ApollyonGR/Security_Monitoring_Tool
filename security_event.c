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
    return choice;
}

int handleSearchMenuChoice(int searchMenuChoice){
    while(1){
    switch(searchMenuChoice){
        case 1:
            printf("\nYou selected choice 1!\n");
            break;
        case 2:
            printf("\nYou selected choice 2!\n");
            break;
        case 3:
            printf("\nYou selected choice 3!\n");
            break;
        case 4:
            printf("\nYou selected choice 4!\n");
            break;
        case 5:
            printf("\nExiting...\n");
            return 5;
        default:
            printf("\nError: Please enter a valid choice\n");
            break;
    
        }
    }
    return 0;
}