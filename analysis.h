#ifndef ANALYSIS_H
#define ANALYSIS_H

#include "security_event.h"

int countEventsByParameter(SecurityEvent events[], int totalEvents, const char *eventType);

int countCriticalEvents(SecurityEvent events[], int totalEvents);
int findHighestSeverity(SecurityEvent events[], int totalEvents);
int countHighestSeverity(SecurityEvent events[], int totalEvents);

int checkFailedLogins (SecurityEvent events[], int totalEvents);
int checkPortScans (SecurityEvent events[], int totalEvents);

int populateSecurityAlerts(SecurityEvent events[], int totalEvents);
int displayAnalysisMenu(FILE *stream, SecurityEvent events[], int totalEvents);

#endif