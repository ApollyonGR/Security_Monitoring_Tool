#include <stdio.h>
#include <stdlib.h>

#include "security_event.h"
#include "analysis.h"
#include "fileio.h"

/*
Figure out why it loops infinitely when I type a letter
*/

int MainMenu(void){
    SecurityEvent events[MAX_EVENTS];
    int total = loadEvents(LOG_RELATIVE_FILEPATH, events, MAX_EVENTS);
    int choice;

    printf("\n"
        "=====================================\n"
        "  CYBR 310 Security Monitoring Tool  \n" 
        "=====================================\n"
        "\n"                                   );

    while(1){
        printf( "1. Load Security Log\n"
                "2. Display All Events\n"
                "3. Search Events\n"
                "4. Analyze Security Events\n"
                "5. Display Security Alerts\n"
                "6. Generate Security Report\n"
                "7. Exit\n");
        printf("\nPlease select option: ");
        scanf("%d", &choice);
        printf("Select which action you'd like to take:\n");
        switch(choice) {
            case 1:
                printf("\nYou picked option 1\n");
                loadEvents(LOG_RELATIVE_FILEPATH, events, MAX_EVENTS);
                break;
            case 2:
                printf("\nYou picked option 2\n");
                return 2;
            case 3:
                printf("\nYou picked option 3\n");
                return 3;
            case 4:
                printf("\nYou picked option 4\n");
                return 4;
            case 5:
                printf("\nYou picked option 5\n");
                return 5;
            case 6: 
                printf("\nYou picked option 6\n");
                return 6;
            case 7:
                printf("\nExiting...\n");
                return 0;
            default:
                printf("\nErr: not valid option\n\n");
                break;
        }
    }
}

int main(void){

    int returnValue = MainMenu();
    printf("%d\n", returnValue);

    return 0;
}