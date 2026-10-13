import os
import time
import shutil
import threading
import psutil
import customtkinter as ctk
from tkinter import messagebox
from plyer import notification
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Set up UI theme
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

DOWNLOADS_PATH = os.path.expanduser("~/Downloads")
QUARANTINE_PATH = os.path.expanduser("~/HyperVision_Quarantine")
os.makedirs(QUARANTINE_PATH, exist_ok=True)

class HyperVisionApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("HyperVision Security Suite | Autonomous EDR & Antivirus")
        self.geometry("900x600")
        self.resizable(False, False)

        # Layout grid
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # Sidebar Navigation
        self.sidebar_frame = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        
        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="🛡️ HYPERVISION", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.pack(padx=20, pady=(30, 20))

        self.btn_dashboard = ctk.CTkButton(self.sidebar_frame, text="Dashboard", command=lambda: self.select_frame("dashboard"))
        self.btn_dashboard.pack(padx=20, pady=10, fill="x")

        self.btn_quarantine = ctk.CTkButton(self.sidebar_frame, text="Quarantine Vault", command=lambda: self.select_frame("quarantine"))
        self.btn_quarantine.pack(padx=20, pady=10, fill="x")

        self.status_indicator = ctk.CTkLabel(self.sidebar_frame, text="● ENGINE ACTIVE", text_color="#2ecc71", font=ctk.CTkFont(size=12, weight="bold"))
        self.status_indicator.pack(side="bottom", pady=30)

        # Frames
        self.dashboard_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.quarantine_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")

        self.setup_dashboard_ui()
        self.setup_quarantine_ui()

        self.select_frame("dashboard")

        # Start Background Protection
        self.start_background_shield()
        self.update_telemetry_loop()

    def select_frame(self, name):
        if name == "dashboard":
            self.dashboard_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
            self.quarantine_frame.grid_forget()
        elif name == "quarantine":
            self.quarantine_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
            self.dashboard_frame.grid_forget()
            self.refresh_quarantine_list()

    def setup_dashboard_ui(self):
        title = ctk.CTkLabel(self.dashboard_frame, text="Endpoint Security Command Center", font=ctk.CTkFont(size=22, weight="bold"))
        title.pack(anchor="nw", pady=(10, 20))

        stats_frame = ctk.CTkFrame(self.dashboard_frame, fg_color="#1a1a1a")
        stats_frame.pack(fill="x", pady=10)

        self.lbl_ram = ctk.CTkLabel(stats_frame, text="System RAM: Loading...", font=ctk.CTkFont(size=14))
        self.lbl_ram.pack(padx=20, pady=15, side="left")

        self.lbl_threats = ctk.CTkLabel(stats_frame, text="Status: Fully Guarded", font=ctk.CTkFont(size=14), text_color="#2ecc71")
        self.lbl_threats.pack(padx=20, pady=15, side="right")

        log_label = ctk.CTkLabel(self.dashboard_frame, text="Live EDR Telemetry & Activity Log:", font=ctk.CTkFont(size=14, weight="bold"))
        log_label.pack(anchor="nw", pady=(20, 5))

        self.log_textbox = ctk.CTkTextbox(self.dashboard_frame, width=620, height=300, fg_color="#111111", text_color="#00ffcc")
        self.log_textbox.pack(anchor="nw", fill="both", expand=True)
        self.log_textbox.insert("0.0", "[*] HyperVision Desktop Application initialized.\n[*] Background file watcher & quarantine vault online.\n")

    def setup_quarantine_ui(self):
        title = ctk.CTkLabel(self.quarantine_frame, text="Isolated Threats Quarantine Vault", font=ctk.CTkFont(size=22, weight="bold"))
        title.pack(anchor="nw", pady=(10, 20))

        self.q_textbox = ctk.CTkTextbox(self.quarantine_frame, width=620, height=400, fg_color="#111111", text_color="#ff5555")
        self.q_textbox.pack(anchor="nw", fill="both", expand=True)

        btn_clear = ctk.CTkButton(self.quarantine_frame, text="Purge Vault (Delete All Threats)", fg_color="#c0392b", hover_color="#962d22", command=self.purge_quarantine)
        btn_clear.pack(anchor="sw", pady=20)

    def log_message(self, message):
        self.log_textbox.insert("end", f"{message}\n")
        self.log_textbox.see("end")

    def update_telemetry_loop(self):
        try:
            ram = psutil.virtual_memory()
            self.lbl_ram.configure(text=f"System RAM Usage: {ram.percent}%")
        except Exception:
            pass
        self.after(3000, self.update_telemetry_loop)

    def refresh_quarantine_list(self):
        self.q_textbox.delete("0.0", "end")
        files = os.listdir(QUARANTINE_PATH)
        if not files:
            self.q_textbox.insert("0.0", "Vault is empty. No threats currently isolated.")
        else:
            for f in files:
                self.q_textbox.insert("end", f"[ISOLATED] {f}\n")

    def purge_quarantine(self):
        for f in os.listdir(QUARANTINE_PATH):
            try:
                os.remove(os.path.join(QUARANTINE_PATH, f))
            except Exception:
                pass
        self.refresh_quarantine_list()
        messagebox.showinfo("Success", "Quarantine vault successfully purged.")

    def start_background_shield(self):
        class ShieldHandler(FileSystemEventHandler):
            def __init__(self, app_instance):
                self.app = app_instance

            def on_created(self, event):
                if event.is_directory:
                    return
                file_path = event.src_path
                time.sleep(1.5)
                if not os.path.exists(file_path):
                    return

                file_name = os.path.basename(file_path)
                ext = os.path.splitext(file_name)[1].lower()
                threat_exts = ['.exe', '.bat', '.vbs', '.scr', '.pif', '.ps1', '.cmd', '.msi']

                if ext in threat_exts:
                    target = os.path.join(QUARANTINE_PATH, file_name)
                    try:
                        shutil.move(file_path, target)
                        self.app.log_message(f"[!] THREAT BLOCKED & QUARANTINED: {file_name}")
                        notification.notify(
                            title="🚨 HyperVision Threat Blocked!",
                            message=f"Malicious file isolated: {file_name}",
                            timeout=10
                        )
                    except Exception as e:
                        self.app.log_message(f"[X] Error quarantining {file_name}: {e}")
                else:
                    self.app.log_message(f"[✓] Safe File Verified: {file_name}")

        def run_observer():
            event_handler = ShieldHandler(self)
            observer = Observer()
            observer.schedule(event_handler, path=DOWNLOADS_PATH, recursive=False)
            observer.start()
            try:
                while True:
                    time.sleep(1)
            except Exception:
                observer.stop()
            observer.join()

        t = threading.Thread(target=run_observer, daemon=True)
        t.start()

if __name__ == "__main__":
    app = HyperVisionApp()
    app.mainloop()
