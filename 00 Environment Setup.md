# Set up guide for development environment step by step, assuming you're starting fresh with either a new MacBook or Windows computer.



# Complete Environment Setup Guide for Beginners

## Part 1: Essential Software Installation

### For MacBook:
1. Install Homebrew (Package Manager):
   - Open Terminal (press Command + Space, type "Terminal")
   - Copy and paste this command:
   ```
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```
   - Press Enter and follow the prompts

### For Windows:
1. Install Package Manager:
   - Open your web browser
   - Go to https://chocolatey.org
   - Click "Get Started"
   - Follow installation instructions for Windows

## Part 2: Required Tools Installation

### For MacBook:
1. Install Git:
   - Open Terminal
   - Type: `brew install git`

2. Install Python:
   - In Terminal, type: `brew install python`

3. Install Node.js:
   - In Terminal, type: `brew install node`

4. Install Visual Studio Code:
   - In Terminal, type: `brew install --cask visual-studio-code`

### For Windows:
1. Install Git:
   - Open Command Prompt as Administrator
   - Type: `choco install git`

2. Install Python:
   - Type: `choco install python`

3. Install Node.js:
   - Type: `choco install nodejs`

4. Install Visual Studio Code:
   - Type: `choco install vscode`

## Part 3: AWS Setup

1. Create AWS Account:
   - Go to https://aws.amazon.com
   - Click "Create an AWS Account"
   - Follow the sign-up process
   - Keep your credentials safe

2. Install AWS CLI:
   - For MacBook:
     ```
     brew install awscli
     ```
   - For Windows:
     ```
     choco install awscli
     ```

3. Configure AWS:
   - Open Terminal/Command Prompt
   - Type: `aws configure`
   - Enter your AWS credentials when prompted

## Part 4: Project Setup

1. Create a Project Directory:
   - Open Terminal/Command Prompt
   - Navigate to where you want to store your project:
     ```
     cd Documents
     mkdir my-auth-project
     cd my-auth-project
     ```

2. Clone the Project (if you have a repository URL):
   ```
   git clone <your-repository-url>
   ```

3. Set Up Python Environment:
   ```
   python -m venv venv
   ```
   - For MacBook:
     ```
     source venv/bin/activate
     ```
   - For Windows:
     ```
     venv\Scripts\activate
     ```

4. Install Python Dependencies:
   ```
   pip install -r requirements.txt
   ```

5. Install Node.js Dependencies:
   ```
   npm install
   ```

## Part 5: Database Setup

1. Install PostgreSQL:
   - For MacBook:
     ```
     brew install postgresql
     brew services start postgresql
     ```
   - For Windows:
     ```
     choco install postgresql
     ```

2. Create Database:
   - Open Terminal/Command Prompt
   - Type: `psql postgres`
   - In the PostgreSQL prompt:
     ```
     CREATE DATABASE authdb;
     \q
     ```

## Part 6: Environment Variables

1. Create Environment File:
   - Open Visual Studio Code:
     ```
     code .env
     ```
   - Add these variables (replace values in <> with your actual values):
     ```
     DATABASE_URL=postgresql://localhost/authdb
     AWS_ACCESS_KEY_ID=<your-aws-access-key>
     AWS_SECRET_ACCESS_KEY=<your-aws-secret-key>
     AWS_REGION=<your-aws-region>
     ```

## Part 7: Running the Application

1. Start Backend:
   ```
   python -m uvicorn app.main:app --reload
   ```

2. Start Frontend:
   - Open new Terminal/Command Prompt window
   ```
   npm start
   ```

## Troubleshooting Common Issues

1. If Python command not found:
   - Restart Terminal/Command Prompt
   - Make sure Python is in your PATH

2. If npm command not found:
   - Reinstall Node.js
   - Restart Terminal/Command Prompt

3. If database connection fails:
   - Make sure PostgreSQL service is running
   - Check database credentials in .env file

4. If AWS commands fail:
   - Verify AWS credentials are correctly configured
   - Check internet connection

## Next Steps

1. Test the Setup:
   - Open web browser
   - Go to http://localhost:3000 for frontend
   - Go to http://localhost:8000/docs for backend API documentation

2. Version Control:
   - Initialize git repository (if not cloned):
     ```
     git init
     git add .
     git commit -m "Initial setup"
     ```

Need help? Reach out to your development team or check the project documentation.


I've created a comprehensive guide that walks you through setting up your development environment from scratch. This guide is suitable for both MacBook and Windows users with no prior technical experience. 

Would you like me to explain any particular section in more detail? Also, if you're starting with either MacBook or Windows specifically, I can provide more focused instructions for your platform.
