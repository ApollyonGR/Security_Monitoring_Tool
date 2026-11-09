#ifndef SECURITY_EVENT_H
#define SECURITY_EVENT_H

#define MAX_EVENTS 50
#define MAX_EVENT_LENGTH 25
#define MAX_USERNAME_LENGTH 10
#define MAX_IP_ADDRESS_LENGTH 16
#define CRITICAL_THRESHOLD 9
#define LOG_RELATIVE_FILEPATH "security.log"

typedef struct {
    char eventType[MAX_EVENT_LENGTH];
    char eventSource[MAX_IP_ADDRESS_LENGTH];
    char accountName[MAX_USERNAME_LENGTH];
    int severity;
} SecurityEvent;

void displayEvent(int i, SecurityEvent events[]);
void displayEvents(SecurityEvent events[], int totalEvents);

int SearchMenu();
int handleSearchMenuChoice(int searchMenuChoice, SecurityEvent events[]);

int searchByEventType(SecurityEvent events[], int count, char target[]);
int searchByEventSource(SecurityEvent events[], int count, char target[]);
int searchByEventSeverity(SecurityEvent events[], int count, char target[]);
int searchByAccountName(SecurityEvent events[], int count, char target[]);

#endif 