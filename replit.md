# Cryptographic Analysis Tool

## Overview

This is a comprehensive cryptographic analysis tool built with Streamlit that provides various cipher decryption capabilities and statistical analysis features. The application allows users to analyze encrypted text, decrypt messages using multiple cipher techniques, and perform frequency analysis to break unknown ciphers.

## System Architecture

The application follows a modular Python architecture with a web-based frontend using Streamlit:

### Frontend Architecture
- **Framework**: Streamlit for web interface
- **Visualization**: Matplotlib and Plotly for charts and graphs
- **Layout**: Multi-page application with sidebar navigation
- **Deployment**: Configured for autoscale deployment on Replit

### Backend Architecture
- **Language**: Python 3.11
- **Structure**: Modular design with separate modules for different functionalities
- **Processing**: Real-time text processing and cipher analysis
- **File Handling**: Support for both text input and file uploads

## Key Components

### 1. Cipher Implementations (`ciphers.py`)
- **Caesar Cipher**: Implementation with encryption, decryption, and brute force attack capabilities
- **Vigenère Cipher**: Advanced polyalphabetic cipher with key-based encryption/decryption
- **Substitution Cipher**: Support for monoalphabetic substitution ciphers

### 2. Frequency Analysis (`analysis.py`)
- **Character Frequency Analysis**: Statistical analysis of letter frequencies
- **Bigram/Trigram Analysis**: Analysis of common letter combinations
- **English Language Statistics**: Comparison with standard English frequency patterns
- **Pattern Recognition**: Identification of common cipher patterns

### 3. Text Processing (`utils.py`)
- **TextProcessor**: Comprehensive text cleaning and formatting utilities
- **FileHandler**: File upload and processing capabilities
- **Output Formatting**: Text grouping and readability improvements

### 4. Main Application (`app.py`)
- **Multi-page Interface**: Five distinct sections for different functionalities
- **Interactive Analysis**: Real-time cipher analysis and decryption
- **Visualization**: Graphical representation of frequency analysis results
- **Educational Content**: Information about different cipher types and techniques

## Data Flow

1. **Input Processing**: User provides encrypted text via direct input or file upload
2. **Text Preprocessing**: Text is cleaned and formatted for analysis
3. **Analysis Phase**: Multiple analysis techniques are applied:
   - Character frequency analysis
   - Pattern recognition
   - Cipher type identification
4. **Decryption Attempts**: Various cipher techniques are tried based on analysis results
5. **Results Presentation**: Decrypted text and analysis results are displayed with visualizations

## External Dependencies

### Core Libraries
- **Streamlit**: Web application framework for the user interface
- **Matplotlib**: Static plotting and visualization
- **Plotly**: Interactive charts and graphs
- **NumPy**: Numerical computations and array operations

### System Dependencies
- **Cairo**: Graphics library for rendering
- **FFmpeg**: Multimedia processing capabilities
- **FreeType**: Font rendering
- **Ghostscript**: PostScript and PDF processing
- **GTK3**: GUI toolkit components

## Deployment Strategy

The application uses Replit's autoscale deployment with the following configuration:
- **Runtime**: Python 3.11 environment
- **Port**: 5000 (configured for Streamlit)
- **Execution**: Streamlit server with parallel workflow execution
- **Scaling**: Automatic scaling based on demand

The deployment includes:
- Nix package management for system dependencies
- Streamlit configuration for headless operation
- Workflow automation for seamless deployment

## Security Assessment

**Latest Security Review:** June 23, 2025 (Updated Post-Fixes)  
**Overall Risk Level:** LOW (approved for deployment)

### Security Issues Fixed
- Removed file upload functionality (security risk eliminated)
- Improved session ID generation using cryptographically secure random tokens
- Added input length limits (50,000 characters max)
- Limited parallel workers to 4 for resource management
- Removed sensitive error message details from logs
- Added input validation to text processing functions
- Implemented comprehensive rate limiting system

## Changelog

Changelog:
- June 23, 2025. Initial setup
- June 23, 2025. Added specialized Kryptos cipher analysis module with K4 analysis tools
- June 23, 2025. Integrated PostgreSQL database for storing analysis sessions, key attempts, and results
- June 23, 2025. Enhanced educational content with complete Kryptos sculpture information including all solved sections
- June 23, 2025. Implemented comprehensive key testing system with dictionary attacks, brute force, cipher variants, and parallel processing
- June 23, 2025. Completed comprehensive security analysis and implemented security enhancement framework
- June 23, 2025. Implemented rate limiting system with operation-specific limits and usage tracking
- June 23, 2025. Added 30-minute session timeout with automatic expiration on inactivity
- June 24, 2025. Implemented live JavaScript countdown timer for real-time session timeout display
- June 24, 2025. Configured SSH authentication for GitHub integration with generated ed25519 key

## User Preferences

Preferred communication style: Simple, everyday language.
Navigation preference: Educational Info first, then Text Input & Analysis, with other tools following.