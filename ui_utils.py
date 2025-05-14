from PyQt5.QtWidgets import QFrame, QVBoxLayout, QTextEdit, QScrollArea, QSizePolicy
from PyQt5.QtGui import QFont

def create_scroll_textedit(placeholder="", read_only=True, font_family='Menlo', font_size=12):
    """Creates a QTextEdit inside a QScrollArea, wrapped in a QFrame."""
    frame = QFrame()
    # frame.setFrameShape(QFrame.StyledPanel) # Optional: adds border around the scroll area
    # frame.setFrameShadow(QFrame.Sunken)
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(0)

    text_edit = QTextEdit()
    text_edit.setPlaceholderText(placeholder)
    text_edit.setReadOnly(read_only)
    text_edit.setFont(QFont(font_family, font_size))
    text_edit.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
    text_edit.setLineWrapMode(QTextEdit.WidgetWidth) # Ensure text wraps

    # Make read-only text edits selectable
    if read_only:
         text_edit.setTextInteractionFlags(text_edit.textInteractionFlags() | 1) # Add TextSelectableByMouse

    # We don't strictly need the QScrollArea if QTextEdit handles scrolling well enough
    # However, keeping it maintains the original structure and might offer more control
    scroll_area = QScrollArea()
    scroll_area.setWidgetResizable(True)
    scroll_area.setWidget(text_edit)
    scroll_area.setWidgetResizable(True)
    scroll_area.setStyleSheet("QScrollArea { border: none; }") # Remove scroll area border

    layout.addWidget(scroll_area)

    # Return both the container frame and the text_edit itself for easy access
    return frame, text_edit