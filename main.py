import sys
import os
import logging

# Set QT_IM_MODULE environment variable early if needed
# os.environ["QT_IM_MODULE"] = "none"

from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QLabel, QHBoxLayout, QTabWidget, QComboBox, QMessageBox)
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QFont, QColor, QPalette, QLinearGradient

# --- Configuration Loading ---
# Load config very early, before other modules might need it
try:
    import config_loader
    config = config_loader.load_config()
    # Make config accessible globally via import statement in other modules
    sys.modules['config'] = config
    logging.info("Configuration loaded and placed in sys.modules.")
except Exception as e:
    logging.critical(f"Failed to load initial configuration: {e}", exc_info=True)
    # Show a critical error message and exit?
    app_init_error = QApplication(sys.argv) # Need an app instance for MessageBox
    QMessageBox.critical(None, "启动错误", f"无法加载配置文件: {e}\n应用程序将关闭。")
    sys.exit(1)
    # pass # Attempt to proceed

# --- Module Imports (After config is loaded) ---
from modules import (
    traffic_analysis,
    js_audit,
    process_analysis,
    http_conversion,
    text_processing,
    regex_generation,
    webshell_detection,
    ai_translation,
    source_audit,
    http_replay,
    api_config,
    ai_assistant, # <-- Import the new module
)
from ui_utils import create_scroll_textedit # Import the helper

class CyberSecurityApp(QMainWindow):
    def __init__(self):
        super().__init__()
        # Make config accessible within the main window instance
        self.config = config
        self.init_ui()
        # Apply initial theme
        self.change_theme(self.theme_selector.currentText())

    def init_ui(self):
        self.setWindowTitle('信息安全智能体 v1 (With Assistant)') # Updated Title
        self.setGeometry(200, 200, 1300, 900) # Slightly larger default size
        self.setMinimumSize(QSize(1200, 800))

        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)

        # --- Tab Widget ---
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)

        # --- Create Tabs by Calling Module Functions ---
        # Pass 'self' (the main window instance) to each create_tab function
        ai_assistant.create_tab(self) # <-- Add the assistant tab first? Or last? Let's add first.
        traffic_analysis.create_tab(self)
        js_audit.create_tab(self)
        process_analysis.create_tab(self)
        http_conversion.create_tab(self)
        text_processing.create_tab(self)
        regex_generation.create_tab(self)
        webshell_detection.create_tab(self)
        ai_translation.create_tab(self)
        source_audit.create_tab(self)
        http_replay.create_tab(self)
        api_config.create_tab(self) # Add API config tab

        # --- Bottom Bar (Theme Selector) ---
        bottom_widget = QWidget()
        bottom_layout = QHBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(5, 5, 5, 5)
        bottom_layout.addStretch() # Push to right

        theme_label = QLabel("主题：")
        self.theme_selector = QComboBox()
        # Ensure THEMES exists in config, provide fallback
        available_themes = getattr(self.config, 'THEMES', {"护眼主题": {}}) # Default to avoid crash
        self.theme_selector.addItems(list(available_themes.keys()))
        # Set default theme selection
        default_theme = "护眼主题"
        if default_theme in available_themes:
            self.theme_selector.setCurrentText(default_theme)
        self.theme_selector.currentTextChanged.connect(self.change_theme)

        bottom_layout.addWidget(theme_label)
        bottom_layout.addWidget(self.theme_selector)
        main_layout.addWidget(bottom_widget)

        # --- Status Bar ---
        self.statusBar().showMessage("准备就绪")

    def change_theme(self, theme_name):
        """Applies the selected theme."""
        logging.debug(f"Changing theme to: {theme_name}")
        # Use available_themes defined during init_ui or reload from config
        available_themes = getattr(self.config, 'THEMES', {})
        if theme_name in available_themes:
            theme = available_themes[theme_name]
            stylesheet = self.get_stylesheet(theme)
            self.setStyleSheet(stylesheet)
            # Update assistant history display style based on theme
            if hasattr(self, 'assist_history_display'):
                 bg_color = theme.get('secondary_bg', '#f0f0f0')
                 border_color = theme.get('border_color', '#cccccc')
                 text_color = theme.get('text_color', '#000000')
                 self.assist_history_display.setStyleSheet(f"""
                      QTextEdit {{
                           background-color: {bg_color};
                           border: 1px solid {border_color};
                           color: {text_color};
                      }}
                 """)
            logging.debug("Theme applied.")
        else:
            logging.warning(f"Theme '{theme_name}' not found in configuration.")

    def get_stylesheet(self, theme):
        """Generates the stylesheet string based on the theme dictionary."""
        # Fallback colors if theme dictionary is incomplete
        default_theme = {
            "main_bg": "#1e1e1e", "secondary_bg": "#2d2d2d", "text_color": "#ffffff",
            "accent_color": "#007acc", "border_color": "#404040",
            "button_hover": "#005999", "button_pressed": "#004c80"
        }
        # Ensure all keys exist, using defaults if necessary
        safe_theme = {key: theme.get(key, default_theme.get(key)) for key in default_theme}

        # Adjusted stylesheet from original, ensure it uses safe_theme values
        return f"""
        QMainWindow, QWidget {{
            background-color: {safe_theme['main_bg']};
            color: {safe_theme['text_color']};
            font-family: Menlo, Monaco, 'Courier New', monospace; /* Consistent monospace */
            font-size: 13px; /* Base font size */
        }}
        QFrame {{ /* Style frames used by create_scroll_textedit */
            background-color: transparent; /* Let parent background show */
            border: none;
        }}
        QPushButton {{
            background-color: {safe_theme['accent_color']};
            color: white; /* Ensure contrast */
            border: none;
            padding: 6px 12px; /* Slightly smaller padding */
            border-radius: 4px;
            font-size: 13px;
            min-width: 80px; /* Adjusted min-width */
            margin: 3px;
        }}
        QPushButton:hover {{
            background-color: {safe_theme['button_hover']};
        }}
        QPushButton:pressed {{
            background-color: {safe_theme['button_pressed']};
        }}
        QPushButton:disabled {{
            background-color: #555555; /* Grey out disabled buttons */
            color: #aaaaaa;
        }}
        QTextEdit {{
            background-color: {safe_theme['secondary_bg']};
            color: {safe_theme['text_color']};
            border: 1px solid {safe_theme['border_color']};
            border-radius: 4px;
            padding: 6px; /* Adjusted padding */
            font-family: Menlo, Consolas, 'Courier New', monospace; /* Explicit monospace */
            font-size: 12px; /* Specific size for text edits */
        }}
        /* Style Assistant History Display Specifically if needed */
        /* QTextEdit#assist_history_display {{ font-size: 13px; }} */

        QLabel {{
            color: {safe_theme['text_color']};
            padding: 2px;
            font-size: 13px;
            margin-bottom: 1px;
        }}
        /* Style the labels within QFormLayout specifically */
        QFormLayout QLabel {{
             padding-top: 5px; /* Align form labels better */
        }}
        QScrollArea {{
            background-color: transparent;
            border: none; /* No border around the scroll area itself */
        }}
        QTabWidget::pane {{
            border: 1px solid {safe_theme['border_color']};
            border-radius: 4px;
            background-color: {safe_theme['main_bg']}; /* Pane background same as main */
            padding: 5px;
            margin-top: -1px; /* Overlap with tab bar */
        }}
        QTabBar::tab {{
            background: {safe_theme['main_bg']};
            color: {safe_theme['text_color']};
            padding: 8px 16px;
            border: 1px solid {safe_theme['border_color']};
            border-bottom: none;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
            margin-right: 2px;
            font-size: 12px;
            min-width: 100px; /* Ensure tabs have minimum width */
        }}
        QTabBar::tab:selected {{
            background: {safe_theme['secondary_bg']}; /* Selected tab slightly different bg */
            border-bottom: 1px solid {safe_theme['secondary_bg']}; /* Hide bottom border part */
            /* Maybe add a top border color? */
            /* border-top: 2px solid {safe_theme['accent_color']}; */
        }}
        QTabBar::tab:hover {{
            background-color: {safe_theme['button_hover']}; /* Use button hover for consistency */
            color: white;
        }}
        QComboBox {{
            background-color: {safe_theme['secondary_bg']};
            color: {safe_theme['text_color']};
            border: 1px solid {safe_theme['border_color']};
            border-radius: 4px;
            padding: 4px 8px;
            min-width: 120px;
        }}
        QComboBox:hover {{
            border-color: {safe_theme['accent_color']};
        }}
        QComboBox::drop-down {{
            border: none;
            width: 16px;
        }}
        QComboBox::down-arrow {{
             image: url(none); /* Optionally hide default arrow */
             /* Custom arrow styling if needed */
        }}
        QComboBox QAbstractItemView {{ /* Style the dropdown list */
             background-color: {safe_theme['secondary_bg']};
             color: {safe_theme['text_color']};
             border: 1px solid {safe_theme['border_color']};
             selection-background-color: {safe_theme['accent_color']};
             selection-color: white;
        }}
        QLineEdit {{
            background-color: {safe_theme['secondary_bg']};
            color: {safe_theme['text_color']};
            border: 1px solid {safe_theme['border_color']};
            border-radius: 4px;
            padding: 4px 6px;
            font-size: 13px;
        }}
        QLineEdit:focus {{
             border: 1px solid {safe_theme['accent_color']};
        }}
        QCheckBox {{
            spacing: 5px; /* Space between checkbox and text */
        }}
        QCheckBox::indicator {{
             width: 13px;
             height: 13px;
        }}
        QProgressBar {{
            border: 1px solid {safe_theme['border_color']};
            border-radius: 4px;
            background-color: {safe_theme['secondary_bg']};
            text-align: center;
            color: {safe_theme['text_color']}; /* Make text visible */
            height: 18px;
            font-size: 11px;
            margin: 4px 0;
        }}
        QProgressBar::chunk {{
            background-color: {safe_theme['accent_color']};
            border-radius: 3px;
            margin: 1px; /* Small margin around chunk */
        }}
        QSplitter::handle {{
             background-color: {safe_theme['border_color']};
             width: 3px; /* Make splitter handle thinner */
             margin: 2px 0;
             border-radius: 1px;
        }}
        QSplitter::handle:horizontal {{
             height: 1px;
             width: 3px;
        }}
        QSplitter::handle:vertical {{
             width: 1px;
             height: 3px;
        }}
        QSplitter::handle:hover {{
             background-color: {safe_theme['accent_color']};
        }}
        QStatusBar {{
             font-size: 12px;
        }}
        QMessageBox {{
             background-color: {safe_theme['secondary_bg']}; /* Style message boxes */
        }}
        QMessageBox QLabel {{ /* Style text inside message boxes */
             color: {safe_theme['text_color']};
        }}
        """

    def show_status(self, message, color="#ffffff"): # Default white color
        """Displays a message on the status bar with a specific color."""
        try:
            self.statusBar().showMessage(message)
            # It's often better to set stylesheet on the status bar itself
            # Ensure color is a valid hex code
            if not color.startswith("#") or len(color) not in [4, 7]:
                color = "#ffffff" # Default to white if invalid
            self.statusBar().setStyleSheet(f"color: {color};")
            logging.info(f"Status update: {message}")
        except Exception as e:
             logging.error(f"Failed to update status bar: {e}")


    def closeEvent(self, event):
        """Handle cleanup on application close."""
        logging.info("Close event triggered.")
        # Call cleanup functions from relevant modules if they exist
        # Example for source_audit:
        if hasattr(source_audit, 'cleanup_temp_files'):
            source_audit.cleanup_temp_files(self)

        # Stop any running threads gracefully? (More complex to implement reliably)
        # Iterate through potential thread attributes and stop them
        for attr_name in dir(self):
            if attr_name.endswith("_thread"):
                thread = getattr(self, attr_name, None)
                if isinstance(thread, QThread) and thread.isRunning():
                    logging.info(f"Stopping thread: {attr_name}")
                    try:
                         if hasattr(thread, 'stop'): # Call custom stop method if exists
                              thread.stop()
                         thread.quit() # Ask event loop to exit
                         thread.wait(1000) # Wait up to 1s for graceful exit
                         if thread.isRunning():
                              logging.warning(f"Thread {attr_name} did not exit gracefully, terminating.")
                              thread.terminate() # Force terminate if still running
                              thread.wait() # Wait for termination
                    except Exception as e:
                         logging.error(f"Error stopping thread {attr_name}: {e}")


        super().closeEvent(event)


if __name__ == '__main__':
    # Basic logging setup
    log_level = os.environ.get('LOGLEVEL', 'INFO').upper()
    # Consider writing logs to a file as well for easier debugging
    # log_file = os.path.join(config_loader.get_config_dir(), "sec-ai-app.log") # Log to config dir
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - [%(name)s:%(lineno)d] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        # handlers=[ logging.FileHandler(log_file, encoding='utf-8'), logging.StreamHandler()] # File and console
        handlers=[logging.StreamHandler()] # Console only for now
    )
    # Set logger name for clarity
    log = logging.getLogger("main")

    # Platform specific adjustments from original code
    if sys.platform == 'win32': # More specific check for Windows
        log.info("Detected Windows platform.")
        # sys.argv += ['-platform', 'windows'] # Usually not needed unless forcing platform plugin
    elif sys.platform == 'darwin': # Check for macOS
        log.info("Detected macOS platform.")
        # sys.argv += ['-platform', 'cocoa']

    app = QApplication(sys.argv)
    # Apply a base style like Fusion for consistency across platforms
    app.setStyle('Fusion')

    # Optional: Set application metadata
    app.setApplicationName("SecAI")
    app.setOrganizationName("YourOrg") # Replace if desired

    # --- Critical: Load Environment Variables for CMDB ---
    # Ensure cmdb.py can find the .env or load it here explicitly
    # Loading was moved inside cmdb.py, but double-check if needed here
    # dotenv_path = find_dotenv(filename=".env", raise_error_if_not_found=False)
    # if dotenv_path: load_dotenv(dotenv_path)
    # else: logging.warning(".env file not found in main.py execution context.")

    window = CyberSecurityApp()
    window.show()
    sys.exit(app.exec_())