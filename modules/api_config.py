import logging
import re # For reading config file content
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QPushButton, QLabel, QHBoxLayout,
                             QComboBox, QFormLayout, QLineEdit, QMessageBox)
from PyQt5.QtGui import QFont

# Import config loading/saving functions
import config_loader
# Import config itself to access current values
import config
# Import APIAdapter to trigger its reload mechanism
from api_adapter import APIAdapter

# --- UI Creation and Logic ---
def create_tab(main_window):
    """Creates the API Configuration tab."""
    tab = QWidget()
    layout = QVBoxLayout(tab)
    layout.addWidget(QLabel("API配置", font=QFont("Arial", 16, QFont.Bold)))

    # --- API Type Selector ---
    type_widget = QWidget()
    type_layout = QHBoxLayout(type_widget)
    type_layout.addWidget(QLabel("当前API类型:"))
    main_window.api_type_selector = QComboBox()
    main_window.api_type_selector.addItems(["deepseek", "azure", "qwen", "ollama", "gemini"])
    type_layout.addWidget(main_window.api_type_selector)
    type_layout.addStretch()
    layout.addWidget(type_widget)

    # Spacer
    layout.addSpacing(10)

    # --- Configuration Forms (using QFormLayout for alignment) ---

    # DeepSeek
    main_window.deepseek_config_widget = QWidget()
    deepseek_layout = QFormLayout(main_window.deepseek_config_widget)
    main_window.deepseek_url_input = QLineEdit()
    main_window.deepseek_key_input = QLineEdit()
    main_window.deepseek_key_input.setEchoMode(QLineEdit.Password)
    main_window.deepseek_model_input = QLineEdit()
    deepseek_layout.addRow("API URL:", main_window.deepseek_url_input)
    deepseek_layout.addRow("API Key:", main_window.deepseek_key_input)
    deepseek_layout.addRow("模型 (Model):", main_window.deepseek_model_input)
    layout.addWidget(main_window.deepseek_config_widget)

    # Azure
    main_window.azure_config_widget = QWidget()
    azure_layout = QFormLayout(main_window.azure_config_widget)
    main_window.azure_url_input = QLineEdit()
    main_window.azure_key_input = QLineEdit()
    main_window.azure_key_input.setEchoMode(QLineEdit.Password)
    main_window.azure_version_input = QLineEdit()
    main_window.azure_model_input = QLineEdit() # Deployment Name
    azure_layout.addRow("Endpoint URL:", main_window.azure_url_input)
    azure_layout.addRow("API Key:", main_window.azure_key_input)
    azure_layout.addRow("API Version:", main_window.azure_version_input)
    azure_layout.addRow("部署名称 (Model):", main_window.azure_model_input)
    layout.addWidget(main_window.azure_config_widget)

    # Qwen (Tongyi Qianwen)
    main_window.qwen_config_widget = QWidget()
    qwen_layout = QFormLayout(main_window.qwen_config_widget)
    main_window.qwen_url_input = QLineEdit()
    main_window.qwen_key_input = QLineEdit()
    main_window.qwen_key_input.setEchoMode(QLineEdit.Password)
    main_window.qwen_model_input = QLineEdit()
    qwen_layout.addRow("API URL:", main_window.qwen_url_input)
    qwen_layout.addRow("API Key:", main_window.qwen_key_input)
    qwen_layout.addRow("模型 (Model):", main_window.qwen_model_input)
    layout.addWidget(main_window.qwen_config_widget)

    # Ollama
    main_window.ollama_config_widget = QWidget()
    ollama_layout = QFormLayout(main_window.ollama_config_widget)
    main_window.ollama_url_input = QLineEdit()
    main_window.ollama_model_input = QLineEdit()
    ollama_layout.addRow("API URL (e.g., http://localhost:11434):", main_window.ollama_url_input)
    ollama_layout.addRow("模型 (Model):", main_window.ollama_model_input)
    layout.addWidget(main_window.ollama_config_widget)

    # Gemini
    main_window.gemini_config_widget = QWidget()
    gemini_layout = QFormLayout(main_window.gemini_config_widget)
    main_window.gemini_url_input = QLineEdit()
    main_window.gemini_key_input = QLineEdit()
    main_window.gemini_key_input.setEchoMode(QLineEdit.Password)
    main_window.gemini_model_input = QLineEdit()
    gemini_layout.addRow("API URL:", main_window.gemini_url_input)
    gemini_layout.addRow("API Key:", main_window.gemini_key_input)
    gemini_layout.addRow("模型 (Model):", main_window.gemini_model_input)
    layout.addWidget(main_window.gemini_config_widget)

    # --- Save Button ---
    layout.addSpacing(20)
    main_window.save_api_btn = QPushButton("保存API配置")
    layout.addWidget(main_window.save_api_btn)

    # Stretch to push elements up
    layout.addStretch(1)

    # --- Connect Signals ---
    main_window.api_type_selector.currentTextChanged.connect(lambda api_type: change_api_view(main_window, api_type))
    main_window.save_api_btn.clicked.connect(lambda: save_api_config(main_window))

    # --- Initial Load ---
    load_api_config_values(main_window) # Load current values into fields
    change_api_view(main_window, config.API_TYPE) # Show the correct view

    main_window.tab_widget.addTab(tab, "API配置")

def change_api_view(main_window, api_type):
    """Shows/Hides the relevant config form based on selected API type."""
    main_window.deepseek_config_widget.setVisible(api_type == "deepseek")
    main_window.azure_config_widget.setVisible(api_type == "azure")
    main_window.qwen_config_widget.setVisible(api_type == "qwen")
    main_window.ollama_config_widget.setVisible(api_type == "ollama")
    main_window.gemini_config_widget.setVisible(api_type == "gemini")
    logging.debug(f"API config view changed to: {api_type}")

def load_api_config_values(main_window):
    """Loads current config values from the 'config' module into the input fields."""
    try:
        # Ensure config module is up-to-date (might have been reloaded)
        # import importlib
        # importlib.reload(config) # Be cautious with reloading

        # Set selector first
        current_api_type = getattr(config, 'API_TYPE', 'qwen')
        main_window.api_type_selector.setCurrentText(current_api_type)

        # Load values, providing defaults if attributes are missing
        # DeepSeek
        main_window.deepseek_url_input.setText(getattr(config, 'DEEPSEEK_API_URL', ''))
        main_window.deepseek_key_input.setText(getattr(config, 'DEEPSEEK_API_KEY', ''))
        main_window.deepseek_model_input.setText(getattr(config, 'DEEPSEEK_MODEL', ''))

        # Azure
        main_window.azure_url_input.setText(getattr(config, 'AZURE_API_URL', ''))
        main_window.azure_key_input.setText(getattr(config, 'AZURE_API_KEY', ''))
        main_window.azure_version_input.setText(getattr(config, 'AZURE_API_VERSION', '2024-10-21'))
        main_window.azure_model_input.setText(getattr(config, 'AZURE_MODEL', ''))

        # Qwen
        main_window.qwen_url_input.setText(getattr(config, 'QWEN_API_URL', ''))
        main_window.qwen_key_input.setText(getattr(config, 'QWEN_API_KEY', ''))
        main_window.qwen_model_input.setText(getattr(config, 'QWEN_MODEL', ''))

        # Ollama
        main_window.ollama_url_input.setText(getattr(config, 'OLLAMA_API_URL', 'http://localhost:11434/api/chat'))
        main_window.ollama_model_input.setText(getattr(config, 'OLLAMA_MODEL', 'qwen2.5-coder:14b'))

        # Gemini
        main_window.gemini_url_input.setText(getattr(config, 'GEMINI_API_URL', 'https://generativelanguage.googleapis.com/v1beta'))
        main_window.gemini_key_input.setText(getattr(config, 'GEMINI_API_KEY', ''))
        main_window.gemini_model_input.setText(getattr(config, 'GEMINI_MODEL', 'gemini-2.0-flash'))

        logging.info("Loaded existing API configurations into UI fields.")

    except Exception as e:
        logging.error(f"Failed to load API config values into UI: {e}", exc_info=True)
        QMessageBox.warning(main_window, "加载配置错误", f"无法加载API配置值:\n{e}")


def save_api_config(main_window):
    """Saves the API configuration from the UI fields back to the config.py file."""
    selected_api_type = main_window.api_type_selector.currentText()
    logging.info(f"Attempting to save API configuration for type: {selected_api_type}")

    try:
        config_path = config_loader.get_config_path()
        # Read the current content
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config_content = f.read()
        except FileNotFoundError:
             logging.error(f"Config file {config_path} not found during save attempt.")
             QMessageBox.critical(main_window, "保存失败", f"配置文件丢失:\n{config_path}")
             return
        except Exception as e:
             logging.error(f"Error reading config file {config_path} for saving: {e}", exc_info=True)
             QMessageBox.critical(main_window, "保存失败", f"读取配置文件时出错:\n{e}")
             return


        # Update API_TYPE first
        config_content = config_loader.update_config_value(config_content, 'API_TYPE', selected_api_type)

        # Update values based on the selected type
        if selected_api_type == "deepseek":
            config_content = config_loader.update_config_value(config_content, 'DEEPSEEK_API_URL', main_window.deepseek_url_input.text())
            config_content = config_loader.update_config_value(config_content, 'DEEPSEEK_API_KEY', main_window.deepseek_key_input.text())
            config_content = config_loader.update_config_value(config_content, 'DEEPSEEK_MODEL', main_window.deepseek_model_input.text())
        elif selected_api_type == "azure":
            config_content = config_loader.update_config_value(config_content, 'AZURE_API_URL', main_window.azure_url_input.text())
            config_content = config_loader.update_config_value(config_content, 'AZURE_API_KEY', main_window.azure_key_input.text())
            config_content = config_loader.update_config_value(config_content, 'AZURE_API_VERSION', main_window.azure_version_input.text())
            config_content = config_loader.update_config_value(config_content, 'AZURE_MODEL', main_window.azure_model_input.text())
        elif selected_api_type == "qwen":
            config_content = config_loader.update_config_value(config_content, 'QWEN_API_URL', main_window.qwen_url_input.text())
            config_content = config_loader.update_config_value(config_content, 'QWEN_API_KEY', main_window.qwen_key_input.text())
            config_content = config_loader.update_config_value(config_content, 'QWEN_MODEL', main_window.qwen_model_input.text())
        elif selected_api_type == "ollama":
            config_content = config_loader.update_config_value(config_content, 'OLLAMA_API_URL', main_window.ollama_url_input.text())
            config_content = config_loader.update_config_value(config_content, 'OLLAMA_MODEL', main_window.ollama_model_input.text())
        elif selected_api_type == "gemini":
            config_content = config_loader.update_config_value(config_content, 'GEMINI_API_URL', main_window.gemini_url_input.text())
            config_content = config_loader.update_config_value(config_content, 'GEMINI_API_KEY', main_window.gemini_key_input.text())
            config_content = config_loader.update_config_value(config_content, 'GEMINI_MODEL', main_window.gemini_model_input.text())

        # Save the modified content back to the file
        if config_loader.save_config_content(config_content):
            # --- Reload Config and Notify Adapters ---
            # 1. Reload the config module itself
            global config
            try:
                # Force Python to reload the module from the updated file
                import importlib
                config = importlib.reload(config)
                # Update the reference in sys.modules if necessary (might not be needed with direct import)
                import sys
                sys.modules['config'] = config
                logging.info("Configuration module reloaded successfully.")

                # 2. Trigger reload in APIAdapter instances (if needed)
                # We can reinstantiate adapters or add a reload method.
                # The current APIAdapter reloads config on each call, which is simpler.
                # Or, if we had a central adapter instance: main_window.api_adapter.reload_config()

                main_window.show_status("API配置保存成功，已生效", "#2ed573")
                QMessageBox.information(main_window, "保存成功", "API配置已成功保存并重新加载。")

            except Exception as e:
                 logging.error(f"Failed to reload config module after saving: {e}", exc_info=True)
                 QMessageBox.warning(main_window, "重载失败", f"配置已保存，但重新加载时出错:\n{e}\n请重启应用使更改完全生效。")

        else:
            QMessageBox.critical(main_window, "保存失败", "无法将更改写入配置文件。")


    except Exception as e:
        logging.error(f"Unexpected error during API config save: {e}", exc_info=True)
        QMessageBox.critical(main_window, "保存失败", f"保存API配置时发生意外错误:\n{e}")
        main_window.show_status(f"保存API配置失败: {e}", "red")
