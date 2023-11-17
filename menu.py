import os
import subprocess
import time
import threading
from threading import Thread


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
def main():
    display_menu()
    global Analysis, Zeek, Proxy
    interface = input("enter the interface: ")
    Proxy = Thread(target=(run_proxy()))
    Analysis = Thread(target=run_analysis())
    Zeek = Thread(target=run_zeek(interface))
    Proxy.start()
    Zeek.start()
    Analysis.start()




def run_analysis():
    time.sleep(300)
    while True:
        os.system("python3 analiz_core_zeek.py")
        time.sleep(60)
    pass


def run_zeek(interface):
    try:
        subprocess.run(["zeek", "-i", interface], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Произошла ошибка при запуске Zeek: {e}")
    except Exception as e:
        print(f"Неожиданная ошибка: {e}")

        

def run_proxy():
    os.system("python3 ban_ip.py")




if __name__ == "__main__":
    main()
