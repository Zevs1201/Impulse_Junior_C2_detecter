from threading import Thread
from Proxy import start
from parsing_ip_anal import update_server_list
from parsing_ip_anal import PRIHOD_OT_ZEEK
import os
import subprocess
import time


def display_menu():
    os.system('clear')  # Clears the console screen (use 'cls' on Windows)

    print("""
    ___   ___
      / /                                                                                 / /
     / /         _   __        ___                  //      ___        ___               / /                  ___       ( )      ___        __
    / /        // ) )  ) )   //   ) )   //   / /   //     ((   ) )   //___) )           / /     //   / /   / /   ) )   / /     //   ) )   //  ) )
   / /        // / /  / /   //___/ /   //   / /   //       \ \      //                 / /     //   / /   / /   / /   / /     //   / /   //
__/ /___     // / /  / /   //         ((___( (   //     //___) )   ((____        ((___/ /     ((___( (   / /   / /   / /     ((___/ /   //
                                                  
                                                                                          
                                                                 .           :.                       
                                                               .-         .:=.                        
                                                              -+        :-==.                         
                                                            .*+       -=+=-.                          
                                                           =%=     .=*++=-                            
                                                         :#%-    :+**++=-                             
                                                        =%%-   -*#**++=:                              
                                                      :#%#:  -*#***++=.                               
                                                     +##*..=###***++=.                                
                                                   -*##*:=###****++=                                  
                                                 .+#***+*******+++-                                   
                                                -*************+++:                                    
                                              .+************++++:                                     
                                             -************++++=.        ..                            
                                           :+******++++++++++=       :=-                              
                                         .=****+++++++++++++-    .-+*=.                               
                                        :+*++++++++++++++++:  .-+**=.                                 
                                      .=++++++++++++++++++.:=+***=.                                   
                                     -++++++++++++++++++++++***+:                                     
                                   .=+++++++++++++++++++++++++:                                       
                                  .+++++++++++++++++++++++++:                                         
                                  =+++++++++++++++++++++++-.                                           
                                  ++++++++++++++++++++++-.                                             
                                  =+++++++++++++++++++-.                                               
                                  .+++++++++++++++++-.                                                
                                   .-+++++++++++++-.                                                  
                                     .:-=++++=-.                                                                                                                                   
                                                                                      

""")


def run_analysis():
    time.sleep(300)
    while True:
        os.system("python3 analiz_core_zeek.py")
        time.sleep(60)
    pass

def run_zeek():
    try:
        subprocess.run(["zeek", "-i", "docker0"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Произошла ошибка при запуске Zeek: {e}")
    except Exception as e:
        print(f"Неожиданная ошибка: {e}")

        

def main():

    display_menu()
    interfac = input("Введите таргет интерфейс для zeek: ")
    proxy_work= Thread(target=start)
    
    proxy_work.start()
    
    
    Zeek = Thread(target=run_zeek())
    Zeek.start()
    Analysis = Thread(target=run_analysis()) 
    Analysis.start()
    ZEEK_List = Thread(target=PRIHOD_OT_ZEEK)
    update_thread = Thread(target=update_server_list)
    update_thread.start()
    ZEEK_List.start()




if __name__ == "__main__":
    main()
