import customtkinter as ctk
from gui import ModernNetWatchGUI
from queue import Queue

def main():
    # Create a shared queue for communication between Sniffer and GUI
    packet_queue = Queue()

    # Start the GUI
    app = ModernNetWatchGUI(packet_queue)
    app.mainloop()

if __name__ == "__main__":
    main()