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
    print("\nPlease choose an option:")
    print("1. start scanning, enter interface")
    print("2. stop scanning")
    print("3. Exit")

class StoppableThread(threading.Thread):
    def __init__(self, target):
        super(StoppableThread, self).__init__(target=target)
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def stopped(self):
        return self._stop_event.is_set()
def main():
    global Analysis, Zeek, Proxy
    Zeek = StoppableThread(target=run_zeek)
    Analysis = StoppableThread(target=run_analysis)
    Proxy = StoppableThread(target=run_proxy)

    while True:
        display_menu()
        choice = input("Enter your choice (1/2/3): ")

        if choice == '1':
            if not Proxy.is_alive():
                Proxy.start()
            if not Zeek.is_alive():
                Zeek.start()
                time.sleep(1)
            if not Analysis.is_alive():
                Analysis.start()
        elif choice == '2':
            Proxy.stop()
            Zeek.stop()
            Analysis.stop()
        elif choice == '3':
            print("Exiting...")
            Proxy.stop()
            Zeek.stop()
            Analysis.stop()
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")


def run_analysis():
    while not Analysis.stopped():
        time.sleep(150)
        while True:
            os.system("python3 analiz_core_zeek.py")
            time.sleep(60)  
        pass

def run_zeek():
    
    interface = input("enter the interface:")
    while not Zeek.stopped():
        try:
            subprocess.run(["zeek", "-i", interface], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Произошла ошибка при запуске Zeek: {e}")
        except Exception as e:
            print(f"Неожиданная ошибка: {e}")
        pass

def run_proxy():
    while not Proxy.stopped():
        os.system("python3 ban_ip.py")
        pass




if __name__ == "__main__":
    main()