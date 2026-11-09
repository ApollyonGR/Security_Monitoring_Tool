#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "security_event.h"

// Expects pre-validated input, run loadEvents() first.
void displayEvent(int i, SecurityEvent events[])
{
    i -= 1; // Lowers number provided by one to account for 0th index
    printf("%d. %s\n"
           "   IP Address: %s\n"
           "   Username: %s\n"
           "   Severity: %d\n\n",
           i + 1, events[i].eventType, events[i].eventSource,
           events[i].accountName, events[i].severity);
}

void displayEvents(SecurityEvent events[], int totalEvents)
{
    // Defining column headers
    const char *h1 = "ID";
    const char *h2 = "EVENT TYPE";
    const char *h3 = "IP ADDRESS";
    const char *h4 = "USERNAME";
    const char *h5 = "SEVERITY";

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
    for (int i = 0; i < totalWidth; i++)
        printf("-");
    printf("\n");

    // Printing rows
    for (int i = 0; i < totalEvents; i++)
    {
        printf("%-*d%-*s%-*s%-*s%d\n",
               w1, events[i].id,
               w2, events[i].eventType,
               w3, events[i].eventSource,
               w4, events[i].accountName,
               events[i].severity);
    }
}

int SearchMenu()
{
    printf("\n==============="
           "\n  Search Menu  "
           "\n===============\n");

    int choice;
    printf("\n1. Search by Event Type"
           "\n2. Search by Event Source"
           "\n3. Search by Event Severity"
           "\n4. Search by Account Name"
           "\n5. Main Menu\n");

    printf("\nPlease select option: ");
    scanf("%d", &choice);

    // removes first \n before fgets
    for (int c; (c = getchar()) != '\n' && c != EOF;)
        ;

    return choice;
}

// shorthand for Print and Prompt, a helper function that handles user input and it's validation
int pnp(const char *prompt, char *dest, size_t size)
{
    printf("\n%s", prompt);
    fgets(dest, size, stdin);
    dest[strcspn(dest, "\n")] = '\0'; // replaces second \n with \0 after fgets

    return strcmp(dest, "q") != 0; // returns one if it's a search term, or 0 if it's q
}

int handleSearchMenuChoice(SecurityEvent events[], int totalEvents) {
    char target[MAX_EVENT_LENGTH];
    while (1)
    {
        int searchMenuChoice = SearchMenu();
        switch (searchMenuChoice)
        {
        case 1:
            if (!pnp("\nPlease enter the event type you'd like to search, or q to quit: ", target, sizeof(target)))
                return 0; // if the user typed q, exit gracefully.
            printf("\n%d matches found!\n", searchByEventParameter(events, totalEvents, eventType, target));
            break;

        case 2:
            if (!pnp("\nPlease enter the IP address you'd like to search, or q to quit: ", target, sizeof(target)))
                return -1;
            printf("\n%d matches found!\n", searchByEventParameter(events, totalEvents, eventSource, target));
            break;

        case 3:
            if (!pnp("\nPlease enter the severity level you'd like to search, or q to quit: ", target, sizeof(target)))
                return -1;
            printf("\n%d matches found!\n", searchByEventParameter(events, totalEvents, severity, target));
            break;

        case 4:
            if (!pnp("\nPlease enter the account name you'd like to search, or q to quit: ", target, sizeof(target)))
                return -1;
            printf("\n%d matches found!\n", searchByEventParameter(events, totalEvents, accountName, target));
            break;

        case 5:
            printf("\nExiting...\n");
            return 5;

        default:
            printf("\nError: Please enter a valid choice\n");
            break;
        }
    }
}

int searchByEventParameter(SecurityEvent events[], int count, searchValue param, char target[])
{

    if (target == NULL)
    {
        printf("\nError: Invalid event type\n");
        return -1;
    }

    SecurityEvent matchingEvents[count];
    int matches = 0;
    int targetSeverity = 0;
    if (param == severity)
        targetSeverity = atoi(target); // ASCII to integer

    for (int i = 0; i < count; i++)
    {
        int matching = 0;
        if (param == severity)
        {
            if (events[i].severity == targetSeverity) {
                matching = 1;
            }
        } else {
            const char *buff = NULL;
            switch (param)
            {
            case eventType:
                buff = events[i].eventType;
                break;
            case eventSource:
                buff = events[i].eventSource;
                break;
            case accountName:
                buff = events[i].accountName;
                break;
            default:
                return -1;
            }

            if (buff && strcmp(buff, target) == 0)
            {
                matching = 1;
            }
        }

        if (matching) {
            matchingEvents[matches].id = events[i].id;
            strcpy(matchingEvents[matches].eventType, events[i].eventType);
            strcpy(matchingEvents[matches].eventSource, events[i].eventSource);
            strcpy(matchingEvents[matches].accountName, events[i].accountName);
            matchingEvents[matches].severity = events[i].severity;
            matches++;
        }
    }
    if (matches != 0) displayEvents(matchingEvents, matches);
    return matches;
}
