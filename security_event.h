#ifndef SECURITY_EVENT_H
#define SECURITY_EVENT_H

#define MAX_EVENTS 50
#define MAX_EVENT_LENGTH 25
#define MAX_USERNAME_LENGTH 10
#define MAX_IP_ADDRESS_LENGTH 16
#define CRITICAL_THRESHOLD 5
#define LOG_RELATIVE_FILEPATH "security.log"

typedef struct {
    int id;
    char eventType[MAX_EVENT_LENGTH];
    char eventSource[MAX_IP_ADDRESS_LENGTH];
    char accountName[MAX_USERNAME_LENGTH];
    int severity;
} SecurityEvent;

typedef enum {
    eventType,
    eventSource,
    severity,
    accountName
} searchValue;

// Bools for if an alert should be displayed, initialized to off. 
extern int failedLoginAlert;
extern int malwareAlert;
extern int phishingAlert;
extern int portScanAlert;
extern int UnAuthAlert;

void displayEvent(int i, SecurityEvent events[]);
void displayEvents(SecurityEvent events[], int totalEvents);
void displaySecurityAlerts(SecurityEvent events[], int totalEvents);

int SearchMenu(void);
int handleSearchMenu(SecurityEvent events[], int totalEvents);

int searchByEventParameter(SecurityEvent events[], int count, searchValue param, char target[]);


#endif 