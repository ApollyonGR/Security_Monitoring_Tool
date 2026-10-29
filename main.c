#include <stdio.h>
#include <stdlib.h>

int MainMenu(void){
    int choice;

    printf("\n"
        "=====================================\n"
        "  CYBR 310 Security Monitoring Tool  \n" 
        "=====================================\n"
        "\n"                                   );

    while(1){

        printf( "1) Option 1\n"
                "2) Option 2\n"
                "3) Option 3\n");
        printf("\nPlease select option: ");
        scanf("%d", &choice);
        
        switch(choice) {
            case 1:
                printf("\nYou picked option 1\n");
                return 1;
            case 2:
                printf("\nYou picked option 2\n");
                return 2;
            case 3:
                printf("\nYou picked option 3\n");
                return 3;
            default:
                printf("\nErr: not valid option\n\n");
                break;
        }
    }
}

int main(void){

    MainMenu();

    return 0;
}