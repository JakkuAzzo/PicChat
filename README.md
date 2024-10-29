# PicChat

PicChat is a secure messaging application that uses steganography to hide conversation histories within images. It provides users with an intuitive chat interface similar to popular messaging apps while enhancing privacy and security.

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Technologies Used](#technologies-used)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)
- [Contact](#contact)

## Features

- **User Authentication**: Secure user registration and login system using hashed passwords.
- **Real-Time Messaging**: Send and receive messages without page refresh using AJAX.
- **Conversation Management**: Start new conversations, view existing ones, and manage chat histories.
- **Steganography Integration**: Save and restore conversation histories hidden within images using the Stegano library.
- **Responsive UI**: User-friendly interface that adapts to various screen sizes.
- **Security Considerations**: CSRF protection, input validation, and secure session management.

## Prerequisites

Before you begin, ensure you have the following installed:

- Python 3.x
- pip (Python package installer)
- SQLite (optional, if not using the default SQLite database)
- Virtualenv (recommended)

## Installation

1. **Clone the Repository**

```
git clone https://github.com/yourusername/picchat.git cd picchat
```


2. **Create a Virtual Environment**

```
python -m venv venv
```


3. **Activate the Virtual Environment**

- On Windows:

  ```
  venv\Scripts\activate
  ```

- On macOS/Linux:

  ```
  source venv/bin/activate
  ```

4. **Install Dependencies**

```
pip install -r requirements.txt
```


5. **Set Up the Database**

The application uses SQLite by default. The database will be initialized automatically when you run the app for the first time.

6. **Prepare Static Files**

- Ensure you have a base image named `base_image.png` in the `static` folder. This image is used for steganography.

  You can use any standard PNG image. For example, download a sample image and place it in the `static` directory:

  ```
  static/
  └── base_image.png
  ```

## Usage

1. **Run the Application**

```
flask run
```


2. **Access the Application**

Open your web browser and navigate to:

```
http://localhost:5000/
```


3. **Create an Account**

- Click on **Sign Up**.
- Enter a username and password.

4. **Login**

- Use your credentials to log in.

5. **Start a Conversation**

- Use the sidebar to start a new conversation by entering the username of another registered user.

6. **Send Messages**

- Type your message in the input field and send it.
- Messages will appear in the chat window in real-time.

7. **Exit and Save Conversation**

- Click on **Exit Chat**.
- Confirm to save the conversation.
- The conversation will be hidden within an image using steganography.

8. **Restore a Conversation**

- When re-entering a conversation, you'll be prompted to restore previous chats.
- Choose **Yes** to retrieve the hidden messages from the image.

## Project Structure

```
picchat/
 ├── app.py 
 ├── picchat.db 
 ├── schema.sql
 ├── requirements.txt 
 ├── static/ 
             ├── base_image.png 
             │ └── styles.css 
├── templates/ 
               ├── base.html 
               │ 
               ├── index.html 
               │ 
               ├── chat.html 
               │ 
               ├── chat_with.html 
               │ 
               ├── messages.html 
               │ 
               ├── encrypt.html 
               │ 
               ├── restore_chat.html 
               │ 
               └── about.html 
└── images/
```

- **app.py**: Main Flask application file containing routes and logic.
- **picchat.db**: SQLite database file (created after running the app).
- **requirements.txt**: Python dependencies.
- **static/**: Folder containing static files like CSS and images.
- **templates/**: HTML templates for rendering pages.
- **images/**: Folder where steganographed images are stored.

## Technologies Used

- **Python 3.x**
- **Flask**: Web framework used for the application.
- **SQLite**: Database for storing user data and messages.
- **Stegano**: Library for steganography operations.
- **Werkzeug**: Provides password hashing utilities.
- **Flask-WTF**: For CSRF protection.
- **HTML/CSS/JavaScript**: Front-end technologies.
- **jQuery**: For AJAX requests.

## Contributing

Contributions are welcome!

## License

This project is licensed under the **MIT License**.

## Acknowledgments

- **Stegano Library**: For providing easy-to-use steganography functions.
- **Flask Community**: For the extensive documentation and support.

## Contact

For any inquiries or support, please contact:

- **Developer**: Nathan Brown-Bennett
- **Email**: k2110813@kingston.ac.uk